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
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::client::Transport;
use crate::proto::Proto;
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

/// Lex one leading double-quoted string, returning it and the slice after the
/// closing quote.
fn lex_string(value: &str, n: usize) -> Result<(String, &str)> {
    let rest = value
        .strip_prefix('"')
        .ok_or_else(|| err(n, "expected a quoted string"))?;
    let mut out = String::new();
    let mut chars = rest.char_indices();
    loop {
        let (i, c) = chars.next().ok_or_else(|| err(n, "unterminated string"))?;
        match c {
            '"' => return Ok((out, &rest[i + 1..])),
            '\\' => {
                let (_, esc) = chars.next().ok_or_else(|| err(n, "unterminated string"))?;
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
}

/// Lex one scalar from an already-trimmed value slice, rejecting trailing junk.
fn lex_scalar(value: &str, n: usize) -> Result<Scalar> {
    if value == "true" || value == "false" {
        return Ok(Scalar::Bool(value == "true"));
    }
    if value.starts_with('"') {
        let (out, rest) = lex_string(value, n)?;
        if rest.trim().is_empty() {
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

/// Parse a `["a", "b"]` list of quoted strings. A trailing comma is accepted;
/// anything else between the brackets that is not a quoted string is an error.
pub(crate) fn parse_string_list(value: &str, n: usize) -> Result<Vec<String>> {
    let inner = value
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .ok_or_else(|| err(n, "expected a list of quoted strings"))?;
    let mut out = Vec::new();
    let mut rest = inner.trim_start();
    while !rest.is_empty() {
        let (s, after) = lex_string(rest, n)?;
        out.push(s);
        rest = after.trim_start();
        match rest.strip_prefix(',') {
            Some(tail) => rest = tail.trim_start(),
            None if rest.is_empty() => break,
            None => return Err(err(n, "expected `,` between list entries")),
        }
    }
    Ok(out)
}

/// A bare integer no larger than `max`.
#[inline(never)]
fn parse_bounded(value: &str, n: usize, max: u64) -> Result<u64> {
    match lex_scalar(value, n)? {
        Scalar::Int(v) if v <= max => Ok(v),
        Scalar::Int(v) => Err(err(n, &format!("invalid integer `{v}`"))),
        Scalar::Str(_) | Scalar::Bool(_) => Err(err(n, "expected an integer value")),
    }
}

pub(crate) fn parse_int(value: &str, n: usize) -> Result<u16> {
    Ok(parse_bounded(value, n, u16::MAX.into())? as u16)
}

pub(crate) fn parse_u32(value: &str, n: usize) -> Result<u32> {
    Ok(parse_bounded(value, n, u32::MAX.into())? as u32)
}

pub(crate) fn parse_bool(value: &str, n: usize) -> Result<bool> {
    match lex_scalar(value, n)? {
        Scalar::Bool(b) => Ok(b),
        Scalar::Str(_) | Scalar::Int(_) => Err(err(n, "expected a boolean value")),
    }
}

pub(crate) fn err(line: usize, msg: &str) -> crate::Error {
    errf!("config line {line}: {msg}")
}

/// Double-quote a string, escaping `"` and `\`.
pub(crate) fn quote(s: &str) -> String {
    let mut out = String::new();
    quote_into(&mut out, s);
    out
}

/// Append `s` double-quoted, escaping `"` and `\`.
#[inline(never)]
pub(crate) fn quote_into(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Append `key = value` with the value as written.
#[inline(never)]
pub(crate) fn kv_raw(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

/// Append `key = "value"`.
#[inline(never)]
pub(crate) fn kv_quoted(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    quote_into(out, value);
    out.push('\n');
}

/// Append `key = n`.
#[inline(never)]
pub(crate) fn kv_num(out: &mut String, key: &str, n: u64) {
    kv_raw(out, key, &n.to_string());
}

/// Append `key = true` or `key = false`.
#[inline(never)]
pub(crate) fn kv_bool(out: &mut String, key: &str, b: bool) {
    kv_raw(out, key, if b { "true" } else { "false" });
}

/// Start a table: a blank line after any previous content, then the header.
#[inline(never)]
pub(crate) fn table(out: &mut String, header: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(header);
    out.push('\n');
}

/// The position of `name` in the space-separated `names`.
#[inline(never)]
pub(crate) fn lookup(names: &'static str, name: &str) -> Option<usize> {
    names.split(' ').position(|n| n == name)
}

pub(crate) fn parse_proto(value: &str, n: usize) -> Result<Proto> {
    let s = parse_string(value, n)?;
    match s.as_str() {
        "tcp" => Ok(Proto::Tcp),
        "udp" => Ok(Proto::Udp),
        "tap" => Err(err(n, "proto `tap` is not supported in this version")),
        other => Err(err(n, &format!("unknown proto `{other}`"))),
    }
}

fn parse_ip(value: &str, n: usize) -> Result<Ipv4Addr> {
    let s = parse_string(value, n)?;
    Ipv4Addr::from_str(&s).map_err(|_| err(n, &format!("invalid IPv4 address `{s}`")))
}

fn parse_transport(value: &str, n: usize) -> Result<Transport> {
    let s = parse_string(value, n)?;
    match s.as_str() {
        "auto" => Ok(Transport::Auto),
        "udp" => Ok(Transport::Udp),
        "tcp" => Ok(Transport::Tcp),
        other => Err(err(n, &format!("unknown transport `{other}`"))),
    }
}

fn parse_cidr(value: &str, n: usize) -> Result<(Ipv4Addr, u8)> {
    let s = parse_string(value, n)?;
    let invalid = || err(n, &format!("invalid address `{s}` (expected A.B.C.D/N)"));
    let (ip, len) = s.split_once('/').ok_or_else(invalid)?;
    let ip = Ipv4Addr::from_str(ip).map_err(|_| invalid())?;
    let len: u8 = len.parse().map_err(|_| invalid())?;
    if len > 32 {
        return Err(invalid());
    }
    Ok((ip, len))
}

/// How a key's value is parsed and where the record keeps it.
#[derive(Clone, Copy)]
pub(crate) enum Key {
    Str(u8),
    Bool(u8),
    Int(u8),
    /// A relay idle window in whole seconds, at least 1.
    Idle,
    Proto,
    Transport,
    Ip,
    Cidr,
    StrList,
}

/// One in-progress table: a superset of the fields of every table in both
/// grammars. Fields are filled as keys are seen and validated for
/// completeness when the table closes.
#[derive(Default)]
pub(crate) struct Record {
    pub(crate) strs: [Option<String>; 6],
    pub(crate) bools: [Option<bool>; 4],
    pub(crate) ints: [Option<u16>; 1],
    pub(crate) idle: Option<u32>,
    pub(crate) proto: Option<Proto>,
    pub(crate) transport: Option<Transport>,
    pub(crate) ip: Option<Ipv4Addr>,
    pub(crate) address: Option<(Ipv4Addr, u8)>,
    pub(crate) allow: Option<Vec<String>>,
}

impl Record {
    #[inline(never)]
    fn set(&mut self, key: Key, value: &str, n: usize) -> Result<()> {
        match key {
            Key::Str(i) => self.strs[i as usize] = Some(parse_string(value, n)?),
            Key::Bool(i) => self.bools[i as usize] = Some(parse_bool(value, n)?),
            Key::Int(i) => self.ints[i as usize] = Some(parse_int(value, n)?),
            Key::Idle => {
                let secs = parse_u32(value, n)?;
                if secs == 0 {
                    return Err(err(n, "`idle` must be at least 1 second"));
                }
                self.idle = Some(secs);
            }
            Key::Proto => self.proto = Some(parse_proto(value, n)?),
            Key::Transport => self.transport = Some(parse_transport(value, n)?),
            Key::Ip => self.ip = Some(parse_ip(value, n)?),
            Key::Cidr => self.address = Some(parse_cidr(value, n)?),
            Key::StrList => self.allow = Some(parse_string_list(value, n)?),
        }
        Ok(())
    }

    /// The string at `i`, which the table requires; `missing` is the error.
    #[inline(never)]
    pub(crate) fn required(&mut self, i: usize, n: usize, missing: &str) -> Result<String> {
        self.strs[i].take().ok_or_else(|| err(n, missing))
    }
}

/// One table of a grammar.
pub(crate) struct TableDef {
    /// The header as printed in errors: `[client]`, `[[servers]]`.
    pub(crate) label: &'static str,
    /// Whether the table may appear once only.
    pub(crate) single: bool,
    /// Space-separated key names, each with the kind at the same position.
    pub(crate) keys: &'static str,
    pub(crate) kinds: &'static [Key],
}

/// A config grammar: table headers as written inside the brackets
/// (`client`, `[servers]`), each with its definition at the same position.
pub(crate) struct Grammar {
    pub(crate) headers: &'static str,
    pub(crate) tables: &'static [TableDef],
}

/// Walk `text` against `grammar`, calling `close` with each table's index and
/// record when the next header or the end of the file closes it.
pub(crate) fn parse_tables(
    text: &str,
    grammar: &Grammar,
    close: &mut dyn FnMut(usize, &mut Record, usize) -> Result<()>,
) -> Result<()> {
    let mut section: Option<usize> = None;
    let mut seen = [false; 8];
    let mut record = Record::default();
    let mut record_keys: Vec<&str> = Vec::new();

    for (lineno, raw) in text.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        let n = lineno + 1;

        if let Some(header) = line.strip_prefix('[') {
            // A table header closes the previous table.
            if let Some(s) = section {
                close(s, &mut record, n)?;
            }
            record = Record::default();
            record_keys.clear();

            let header = header
                .strip_suffix(']')
                .ok_or_else(|| err(n, "unterminated table header"))?;
            let idx = lookup(grammar.headers, header)
                .ok_or_else(|| err(n, &format!("unknown table header [{header}]")))?;
            let table = &grammar.tables[idx];
            if table.single {
                if seen[idx] {
                    return Err(err(n, &format!("duplicate {} table", table.label)));
                }
                seen[idx] = true;
            }
            section = Some(idx);
            continue;
        }

        let (key, value) = split_kv(line).ok_or_else(|| err(n, "expected key = value"))?;
        if key.is_empty() || key.contains(|c: char| c.is_whitespace()) {
            return Err(err(n, "invalid key"));
        }
        let Some(idx) = section else {
            return Err(err(n, &format!("key `{key}` before any table header")));
        };
        let table = &grammar.tables[idx];
        reject_dup(&mut record_keys, key, n)?;
        let Some(k) = lookup(table.keys, key) else {
            return Err(err(n, &format!("unknown key `{key}` in {}", table.label)));
        };
        record.set(table.kinds[k], value, n)?;
    }

    // Close the final open table at EOF.
    if let Some(s) = section {
        close(s, &mut record, text.lines().count())?;
    }
    Ok(())
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
    match read(path)? {
        Some(text) => parse(&text).map_err(|e| malformed(path, e)),
        None => Ok(T::default()),
    }
}

/// The file's text, or `None` when there is no file.
#[inline(never)]
fn read(path: &Path) -> std::result::Result<Option<String>, LoadError> {
    match std::fs::read_to_string(path) {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(LoadError::Unreadable(errf!("read {}: {e}", path.display()))),
    }
}

#[inline(never)]
fn malformed(path: &Path, e: crate::Error) -> LoadError {
    LoadError::Malformed(errf!("parse {}: {e}", path.display()))
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
        .ok_or_else(|| -> crate::Error { errf!("invalid config path {}", path.display()) })?;
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
        return Err(errf!("save {}: {e}", path.display()));
    }

    // Fsync the directory so the rename is durable across a crash. Best-effort:
    // the data file is already fsynced and in place.
    if let Ok(d) = File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}
