pub const SERVICE_BINARY_PATH: &str = "/usr/local/bin/zeronat";
const SYSTEMD_UNIT: &str = "/etc/systemd/system/zeronat.service";
const INIT_SCRIPT: &str = "/etc/init.d/zeronat";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceManager {
    Systemd,
    OpenRc,
    Procd,
}

impl ServiceManager {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::OpenRc => "OpenRC",
            Self::Procd => "procd",
        }
    }

    pub const fn unit_path(self) -> &'static str {
        match self {
            Self::Systemd => SYSTEMD_UNIT,
            Self::OpenRc | Self::Procd => INIT_SCRIPT,
        }
    }
}

#[derive(Clone)]
pub struct ServiceInstall {
    pub manager: ServiceManager,
    pub version: String,
}

pub fn installed_service_manager(
    systemd_unit_exists: bool,
    init_script: Option<&str>,
) -> Option<ServiceManager> {
    if systemd_unit_exists {
        return Some(ServiceManager::Systemd);
    }
    let first_line = init_script?.lines().next()?;
    if first_line.contains("/etc/rc.common") {
        Some(ServiceManager::Procd)
    } else if first_line.contains("openrc-run") {
        Some(ServiceManager::OpenRc)
    } else {
        None
    }
}

pub fn installed_service_command(manager: ServiceManager, body: &str) -> Option<Vec<String>> {
    let args = match manager {
        ServiceManager::Systemd => body
            .lines()
            .find_map(|line| line.trim().strip_prefix("ExecStart="))?,
        ServiceManager::OpenRc => body
            .lines()
            .find_map(|line| line.trim().strip_prefix("command_args=\""))?
            .strip_suffix('"')?,
        ServiceManager::Procd => body
            .lines()
            .find_map(|line| line.trim().strip_prefix("procd_set_param command "))?,
    };
    let mut command: Vec<String> = args.split_whitespace().map(str::to_string).collect();
    if manager == ServiceManager::OpenRc {
        command.insert(0, SERVICE_BINARY_PATH.to_string());
    }
    command
        .first()
        .is_some_and(|program| program == SERVICE_BINARY_PATH)
        .then_some(command)
}

#[cfg(test)]
mod tests {
    use super::{installed_service_manager, ServiceManager};

    #[test]
    fn identifies_installed_service_files() {
        assert_eq!(
            installed_service_manager(true, None),
            Some(ServiceManager::Systemd)
        );
        assert_eq!(
            installed_service_manager(false, Some("#!/bin/sh /etc/rc.common\n")),
            Some(ServiceManager::Procd)
        );
        assert_eq!(
            installed_service_manager(false, Some("#!/sbin/openrc-run\n")),
            Some(ServiceManager::OpenRc)
        );
        assert_eq!(installed_service_manager(false, Some("#!/bin/sh\n")), None);
    }
}
