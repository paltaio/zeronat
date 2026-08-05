#![cfg(unix)]

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub struct DownloadFile {
    dir: PathBuf,
    path: PathBuf,
    file: File,
    dir_identity: (u64, u64),
    file_identity: (u64, u64),
}

impl DownloadFile {
    pub fn create() -> Result<Self, String> {
        Self::create_in(&std::env::temp_dir(), random_download_name)
    }

    fn create_in(
        parent: &Path,
        mut next_name: impl FnMut() -> Result<String, String>,
    ) -> Result<Self, String> {
        for _ in 0..128 {
            let dir = parent.join(next_name()?);
            match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(format!("failed to create private download directory: {e}"));
                }
            }

            let result = Self::create_file(dir.clone());
            if result.is_err() {
                let _ = std::fs::remove_dir_all(&dir);
            }
            return result;
        }
        Err("could not create a private download directory".into())
    }

    fn create_file(dir: PathBuf) -> Result<Self, String> {
        let dir_meta = std::fs::symlink_metadata(&dir)
            .map_err(|e| format!("failed to inspect private download directory: {e}"))?;
        validate_dir(&dir_meta)?;

        let path = dir.join("artifact");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|e| format!("failed to create private download file: {e}"))?;
        let file_meta = file
            .metadata()
            .map_err(|e| format!("failed to inspect private download file: {e}"))?;
        validate_file(&file_meta, false)?;

        Ok(Self {
            dir,
            path,
            file,
            dir_identity: (dir_meta.dev(), dir_meta.ino()),
            file_identity: (file_meta.dev(), file_meta.ino()),
        })
    }

    pub fn output(&self) -> &File {
        &self.file
    }

    pub fn prepare_install(&mut self) -> Result<&File, String> {
        let dir_meta = std::fs::symlink_metadata(&self.dir)
            .map_err(|e| format!("failed to inspect private download directory: {e}"))?;
        validate_dir(&dir_meta)?;
        if (dir_meta.dev(), dir_meta.ino()) != self.dir_identity {
            return Err("private download directory was replaced".into());
        }

        let path_meta = std::fs::symlink_metadata(&self.path)
            .map_err(|e| format!("failed to inspect downloaded binary: {e}"))?;
        let file_meta = self
            .file
            .metadata()
            .map_err(|e| format!("failed to inspect downloaded binary: {e}"))?;
        validate_file(&path_meta, true)?;
        validate_file(&file_meta, true)?;
        if (path_meta.dev(), path_meta.ino()) != self.file_identity
            || (file_meta.dev(), file_meta.ino()) != self.file_identity
        {
            return Err("downloaded binary was replaced".into());
        }
        self.file
            .seek(SeekFrom::Start(0))
            .map_err(|e| format!("failed to read downloaded binary: {e}"))?;
        Ok(&self.file)
    }
}

impl Drop for DownloadFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn random_download_name() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|e| format!("failed to read the system random source: {e}"))?;
    let mut name = String::from("zeronat-download-");
    for byte in bytes {
        name.push_str(&format!("{byte:02x}"));
    }
    Ok(name)
}

fn validate_dir(meta: &std::fs::Metadata) -> Result<(), String> {
    if !meta.file_type().is_dir() || meta.uid() != effective_uid() || meta.mode() & 0o777 != 0o700 {
        return Err("private download directory owner or permissions changed".into());
    }
    Ok(())
}

fn validate_file(meta: &std::fs::Metadata, require_content: bool) -> Result<(), String> {
    if !meta.file_type().is_file()
        || meta.uid() != effective_uid()
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err("downloaded binary owner, type, permissions, or link count changed".into());
    }
    if require_content && meta.len() == 0 {
        return Err("downloaded binary is empty".into());
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no failure mode and does not dereference memory.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::DownloadFile;
    use std::io::Write as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[test]
    fn skips_preexisting_paths_and_symlinks() {
        let base = test_dir("collisions");
        std::fs::create_dir(base.join("existing")).unwrap();
        std::os::unix::fs::symlink(base.join("existing"), base.join("symlink")).unwrap();
        let names = ["existing", "symlink", "fresh"];
        let mut names = names.into_iter().map(str::to_string);

        let download = DownloadFile::create_in(&base, || {
            names.next().ok_or_else(|| "missing test name".into())
        })
        .unwrap();
        assert_eq!(download.dir, base.join("fresh"));
        assert!(base
            .join("symlink")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink());

        drop(download);
        std::fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn rejects_replaced_downloads() {
        let base = test_dir("replacement");
        let mut download = DownloadFile::create_in(&base, || Ok("private".into())).unwrap();
        download
            .output()
            .try_clone()
            .unwrap()
            .write_all(b"downloaded binary")
            .unwrap();
        let moved = download.dir.join("moved");
        std::fs::rename(&download.path, &moved).unwrap();
        std::os::unix::fs::symlink(&moved, &download.path).unwrap();

        assert!(download.prepare_install().is_err());
        drop(download);
        std::fs::remove_dir_all(base).unwrap();
    }

    fn test_dir(tag: &str) -> PathBuf {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "zeronat-install-test-{}-{tag}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        path
    }
}
