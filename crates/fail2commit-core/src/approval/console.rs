//! Direct console access (FR-002). Prompts and secrets use the controlling
//! terminal (`/dev/tty`, `CONIN$`/`CONOUT$`), never stdin/stdout: stdin
//! carries Git hook tuples or protocol lines and stdout may be captured.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, IsTerminal, Read, Write};
pub use zeroize::Zeroizing;

#[cfg(unix)]
const IN_PATH: &str = "/dev/tty";
#[cfg(unix)]
const OUT_PATH: &str = "/dev/tty";
#[cfg(windows)]
const IN_PATH: &str = "CONIN$";
#[cfg(windows)]
const OUT_PATH: &str = "CONOUT$";

/// Upper bound for one typed line (decision or secret).
pub(crate) const MAX_LINE_BYTES: usize = 1024;

pub(crate) struct Console {
    input: BufReader<File>,
    output: File,
}

impl Console {
    /// The interactive console, or `None` when this process has none
    /// (service, CI, IDE child without a terminal).
    pub(crate) fn open() -> Option<Console> {
        let input = OpenOptions::new()
            .read(true)
            .write(true)
            .open(IN_PATH)
            .ok()?;
        if !input.is_terminal() {
            return None;
        }
        let output = OpenOptions::new()
            .read(true)
            .write(true)
            .open(OUT_PATH)
            .ok()?;
        Some(Console {
            input: BufReader::new(input),
            output,
        })
    }

    pub(crate) fn write_str(&mut self, s: &str) -> std::io::Result<()> {
        self.output.write_all(s.as_bytes())?;
        self.output.flush()
    }

    /// One visible line; `None` on EOF. Over-long lines are an error.
    pub(crate) fn read_line(&mut self) -> std::io::Result<Option<String>> {
        let mut buf = Vec::new();
        (&mut self.input)
            .take(MAX_LINE_BYTES as u64 + 1)
            .read_until(b'\n', &mut buf)?;
        if buf.is_empty() {
            return Ok(None);
        }
        if buf.len() > MAX_LINE_BYTES {
            return Err(std::io::Error::other("input line too long"));
        }
        Ok(Some(String::from_utf8_lossy(&buf).trim().to_string()))
    }
}

/// Whether an interactive console is reachable from this process.
pub fn interactive() -> bool {
    Console::open().is_some()
}

/// Read one secret with echo disabled from the console. Fails closed
/// (`ApprovalUnavailable`) without a console.
pub fn read_secret(prompt: &str) -> crate::Result<Zeroizing<String>> {
    if !interactive() {
        return Err(crate::Error::approval_unavailable(
            "no interactive console for hidden input",
        ));
    }
    let s = rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| crate::Error::rejected(format!("could not read hidden input: {e}")))?;
    if s.len() > MAX_LINE_BYTES {
        return Err(crate::Error::invalid("input too long"));
    }
    Ok(s)
}

/// Write text (e.g. a one-time recovery code) to the console only, so it
/// never reaches stdout/stderr captures or `--json` output.
pub fn show_secret(text: &str) -> crate::Result<()> {
    let mut c = Console::open().ok_or_else(|| {
        crate::Error::approval_unavailable("no interactive console to display the secret")
    })?;
    c.write_str(text)
        .map_err(|e| crate::Error::internal(format!("console write failed: {e}")))
}

/// Make untrusted text (ref names, package names, evidence) safe to print:
/// strip URL credentials and escape control characters so terminal escape
/// sequences cannot rewrite the prompt.
pub fn sanitize(text: &str) -> String {
    let text = crate::redact::redact_url_credentials(text);
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control()
            || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.push_str(&format!("\\u{{{:x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}
