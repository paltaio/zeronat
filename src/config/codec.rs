//! Value-agnostic half of the config codec: comment stripping, `key = value`
//! splitting, the scalar lexer, quoting, and crash-safe load/save. Each config
//! grammar layers its tables and keys on top.
//!
//! The lexer is total over arbitrary input: it never panics, never loops
//! forever, and scans by `char` so it never indexes a non-char-boundary in
//! multibyte UTF-8. Any malformed input is a hard error, mirroring the
//! reject-on-malformed posture of the binary codec.

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::Result;

/// Unique-per-attempt suffix for atomic-save temp files, so concurrent saves in
/// the same process never collide on the temp name.
pub(super) static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A parsed scalar value: a double-quoted string, a bare unsigned integer, or a
/// bare `true`/`false`. A scalar of the wrong kind surfaces as a clear type
/// error from the typed accessors rather than a parse error.
enum Scalar {
    Str(String),
    Int(u64),
    Bool(bool),
}

pub(crate) fn reject_dup<'a>(seen: &mut Vec<&'a str>, key: &'a str, n: usize) -> Result<()> {
    if seen.contains(&key) {
        return Err(err(n, &format!("duplicate key `{key}`")));
    }
    seen.push(key);
    Ok(())
}

/// Drop a `#` comment that begins outside a quoted string. A `#` inside `"..."`
/// is literal. Scans by char so the returned slice always ends on a char
/// boundary.
pub(crate) fn strip_comment(line: &str) -> &str {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '#' {
            return &line[..i];
        }
    }
    line
}

/// Split a `key = value` line on the first `=` that is outside a quoted string.
/// A key never contains `=`; values are quoted strings or bare integers.
pub(crate) fn split_kv(line: &str) -> Option<(&str, &str)> {
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in line.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        } else if c == '=' {
            return Some((line[..i].trim(), line[i + 1..].trim()));
        }
    }
    None
}

/// Lex one scalar from an already-trimmed value slice, rejecting trailing junk.
fn lex_scalar(value: &str, n: usize) -> Result<Scalar> {
    if value == "true" || value == "false" {
        return Ok(Scalar::Bool(value == "true"));
    }
    if let Some(rest) = value.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars();
        loop {
            let c = chars.next().ok_or_else(|| err(n, "unterminated string"))?;
            match c {
                '"' => break,
                '\\' => {
                    let esc = chars.next().ok_or_else(|| err(n, "unterminated string"))?;
                    match esc {
                        '"' => out.push('"'),
                        '\\' => out.push('\\'),
                        other => {
                            return Err(err(n, &format!("invalid string escape `\\{other}`")));
                        }
                    }
                }
                c if (c as u32) < 0x20 => {
                    return Err(err(n, "control character in string"));
                }
                c => out.push(c),
            }
        }
        if chars.as_str().trim().is_empty() {
            Ok(Scalar::Str(out))
        } else {
            Err(err(n, "trailing characters after string value"))
        }
    } else {
        // Bare integer; parse via str::parse so overflow/sign/empty all reject.
        let v = value
            .parse::<u64>()
            .map_err(|_| err(n, &format!("invalid integer `{value}`")))?;
        Ok(Scalar::Int(v))
    }
}

pub(crate) fn parse_string(value: &str, n: usize) -> Result<String> {
    match lex_scalar(value, n)? {
        Scalar::Str(s) => Ok(s),
        Scalar::Int(_) | Scalar::Bool(_) => Err(err(n, "expected a string value")),
    }
}

pub(crate) fn parse_int(value: &str, n: usize) -> Result<u16> {
    match lex_scalar(value, n)? {
        Scalar::Int(v) => u16::try_from(v).map_err(|_| err(n, &format!("invalid integer `{v}`"))),
        Scalar::Str(_) | Scalar::Bool(_) => Err(err(n, "expected an integer value")),
    }
}

pub(crate) fn parse_u32(value: &str, n: usize) -> Result<u32> {
    match lex_scalar(value, n)? {
        Scalar::Int(v) => u32::try_from(v).map_err(|_| err(n, &format!("invalid integer `{v}`"))),
        Scalar::Str(_) | Scalar::Bool(_) => Err(err(n, "expected an integer value")),
    }
}

pub(crate) fn parse_bool(value: &str, n: usize) -> Result<bool> {
    match lex_scalar(value, n)? {
        Scalar::Bool(b) => Ok(b),
        Scalar::Str(_) | Scalar::Int(_) => Err(err(n, "expected a boolean value")),
    }
}

pub(crate) fn err(line: usize, msg: &str) -> crate::Error {
    format!("config line {line}: {msg}").into()
}

/// Double-quote a string, escaping `"` and `\`.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Why a config could not be loaded, kept distinct because the safe recovery
/// differs: an unreadable file still holds intact state that must not be
/// clobbered, while a malformed one is recoverable only by setting it aside.
#[derive(Debug)]
pub enum LoadError {
    /// Present but unreadable (permission, transient IO). Contents are intact.
    Unreadable(crate::Error),
    /// Read but unparseable. The bytes survive; the config does not.
    Malformed(crate::Error),
}

/// Load a config file through `parse`. A missing file yields the default
/// (empty) config so a first boot with `--config` pointing at a not-yet-written
/// path is not an error; the file is created on the first persisted mutation.
pub(crate) fn load<T: Default>(
    path: &Path,
    parse: impl FnOnce(&str) -> Result<T>,
) -> std::result::Result<T, LoadError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(T::default()),
        Err(e) => {
            return Err(LoadError::Unreadable(
                format!("read {}: {e}", path.display()).into(),
            ))
        }
    };
    parse(&text).map_err(|e| LoadError::Malformed(format!("parse {}: {e}", path.display()).into()))
}

/// Best-effort move of an unparseable config aside (`<name>.corrupt-<unixsecs>`)
/// so its contents stay recoverable before the server writes a fresh file in its
/// place. Returns the backup path on success.
pub fn quarantine(path: &Path) -> Option<std::path::PathBuf> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut name = path.file_name()?.to_os_string();
    name.push(format!(".corrupt-{ts}"));
    let backup = path.with_file_name(name);
    std::fs::rename(path, &backup).ok().map(|_| backup)
}

/// Write `text` to `path` crash-safely: write a same-directory temp file, fsync
/// its data, rename it over the target, then fsync the parent directory so the
/// rename itself survives a crash. The temp file takes the target's existing
/// mode before the rename (owner-only for a fresh file: every config carries
/// secrets), so a save never widens the file's permissions.
pub fn save_atomic(path: &Path, text: &str) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| -> crate::Error {
            format!("invalid config path {}", path.display()).into()
        })?;
    let tmp = dir.join(format!(
        ".{}.{}.{}.tmp",
        file_name,
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));

    let write = || -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let mode = match std::fs::metadata(path) {
            Ok(meta) => meta.permissions().mode(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0o600,
            Err(e) => return Err(e.into()),
        };
        let mut f = File::create(&tmp)?;
        // fchmod after create: the open(2) mode is masked by the umask, and
        // the file is still empty here, so no secret bytes are ever readable
        // through the default-mode window.
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.write_all(text.as_bytes())?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    };

    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("save {}: {e}", path.display()).into());
    }

    // Fsync the directory so the rename is durable across a crash. Best-effort:
    // the data file is already fsynced and in place.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
