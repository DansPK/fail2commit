//! `fail2commit rules check | list` (FR-019, SPEC-015).
//!
//! Rule files are trusted settings: the bundled set plus `*.yar` / `*.yara`
//! in `<config dir>/rules/`. Nothing in the current directory or project is
//! ever read as a rule.

use super::{CmdResult, Ctx, Outcome};
use fail2commit_core::scan::yara::{self, Matcher};
use fail2commit_core::Error;

#[derive(clap::Args, Debug)]
pub struct Args {
    #[command(subcommand)]
    pub action: Action,
}

#[derive(clap::Subcommand, Debug)]
pub enum Action {
    /// Compile the bundled rules and every file in the rules folder.
    Check,
    /// List every rule a guarded install matches against.
    List,
}

pub fn run(ctx: &Ctx, args: Args) -> CmdResult {
    let dir = yara::user_rules_dir(&ctx.paths);
    match args.action {
        Action::Check => {
            let files = yara::check(&ctx.paths)?;
            let mut text = format!("rules folder: {}", dir.display());
            let mut bad = Vec::new();
            for f in &files {
                match &f.error {
                    None => text.push_str(&format!("\nok    {} ({} rule(s))", f.file, f.rules)),
                    Some(e) => {
                        text.push_str(&format!("\nerror {e}"));
                        bad.push(e.clone());
                    }
                }
            }
            let data = serde_json::json!({
                "folder": dir,
                "files": files.iter().map(|f| serde_json::json!({
                    "file": f.file, "rules": f.rules, "error": f.error,
                })).collect::<Vec<_>>(),
            });
            if !bad.is_empty() {
                return Err(Error::invalid(format!(
                    "{text}\n{} rule file(s) do not compile; guarded installs stop until they are fixed",
                    bad.len()
                )));
            }
            if !ctx.settings.rules.enabled {
                text.push_str("\nnote: rules.enabled = false; installs do not match rules");
            }
            Ok(Outcome {
                message: text,
                data,
                ..Default::default()
            })
        }
        Action::List => {
            // A broken user file is reported by `check`; list what compiles.
            let m = match Matcher::load(
                &ctx.paths,
                &fail2commit_core::settings::RuleSettings { enabled: true },
            ) {
                Ok(Some(m)) => m,
                Ok(None) => Matcher::bundled(),
                Err(e) => {
                    return Err(Error::invalid(format!(
                        "{}; run `fail2commit rules check`",
                        e.message
                    )))
                }
            };
            let rules = m.rules();
            let mut text = format!("rules folder: {}", dir.display());
            for r in &rules {
                text.push_str(&format!(
                    "\n{}:{} - {}",
                    r.namespace, r.identifier, r.description
                ));
            }
            text.push_str(&format!("\n{} rule(s)", rules.len()));
            if !ctx.settings.rules.enabled {
                text.push_str("; rules.enabled = false, installs do not match them");
            }
            Ok(Outcome {
                message: text,
                data: serde_json::json!({
                    "folder": dir,
                    "enabled": ctx.settings.rules.enabled,
                    "rules": rules.iter().map(|r| serde_json::json!({
                        "namespace": r.namespace,
                        "identifier": r.identifier,
                        "description": r.description,
                    })).collect::<Vec<_>>(),
                }),
                ..Default::default()
            })
        }
    }
}
