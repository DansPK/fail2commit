//! `fail2commit api`: one versioned JSON Request on stdin, line-delimited
//! `ServerMessage`s on stdout (CHORE-001, coordinator-owned). Approvals use
//! the stdio channel: `approval_request` lines out, `ClientMessage` lines in
//! (implemented by T-002 behind `ApproverChoice::Stdio`).

use clap::Parser;
use fail2commit_core::protocol::{Request, ServerMessage, MAX_MESSAGE_BYTES, PROTOCOL_VERSION};
use fail2commit_core::Error;
use std::io::{BufRead, Read, Write};

pub fn run() -> i32 {
    let response = match read_request() {
        Ok(req) => {
            let id = Some(req.id.clone());
            match route(req) {
                Ok(cli) => crate::execute(cli, id),
                Err(e) => super::error_response(e, id),
            }
        }
        Err(e) => super::error_response(e, None),
    };
    emit(&ServerMessage::Result(response.clone()));
    response.exit_status()
}

pub fn emit(msg: &ServerMessage) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(
        out,
        "{}",
        serde_json::to_string(msg).expect("message serializes")
    );
    let _ = out.flush();
}

fn read_request() -> fail2commit_core::Result<Request> {
    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut handle = stdin.lock().take(MAX_MESSAGE_BYTES as u64 + 1);
    handle.read_line(&mut line)?;
    if line.len() > MAX_MESSAGE_BYTES {
        return Err(Error::invalid("request exceeds MAX_MESSAGE_BYTES"));
    }
    // Windows shells may prepend a UTF-8 BOM when piping.
    let req: Request = serde_json::from_str(line.trim_start_matches('\u{feff}').trim_end())
        .map_err(|e| Error::invalid(format!("bad request: {e}")))?;
    if req.version != PROTOCOL_VERSION {
        return Err(Error::invalid(format!(
            "unsupported protocol version {}",
            req.version
        )));
    }
    Ok(req)
}

fn route(req: Request) -> fail2commit_core::Result<crate::Cli> {
    if let Some(cwd) = &req.cwd {
        std::env::set_current_dir(cwd).map_err(|e| Error::invalid(format!("cwd: {e}")))?;
    }
    if req
        .argv
        .iter()
        .any(|a| a == "--approver" || a.starts_with("--approver=") || a == "api")
    {
        return Err(Error::invalid(
            "api requests choose neither the approver nor nested api",
        ));
    }
    let argv = ["fail2commit", "--json", "--approver", "stdio"]
        .into_iter()
        .map(String::from)
        .chain(req.argv);
    crate::Cli::try_parse_from(argv).map_err(|e| Error::invalid(e.to_string()))
}
