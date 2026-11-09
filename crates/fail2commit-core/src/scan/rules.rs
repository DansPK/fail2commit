//! Git force-push evidence rules for lifecycle scripts (T-006, SPEC-006).
//!
//! These rules are *evidence*, not an execution boundary. A script can reach a
//! forced push through a form this module does not model (an obfuscated string,
//! a downloaded helper, an aliased subcommand). Enforcement stays with the Git
//! shim and the sandboxed run (FR-001, SPEC-007); a hit here only means the
//! script is denied outright.
//!
//! Everything is pure CPU over caller-supplied text: no filesystem access, no
//! process execution, no unbounded work.

/// Characters examined from one logical line (a longer line is truncated).
const MAX_LINE_CHARS: usize = 4096;
/// Physical lines joined through `\` continuations before analysis.
const MAX_JOINED_LINES: usize = 8;

/// One force-push form found in a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForceHit {
    /// One-based line number of the first physical line of the command.
    pub line: usize,
    /// Stable short name of the matched form, for reports.
    pub form: &'static str,
    /// Command text, trimmed and truncated. Callers still redact it.
    pub text: String,
}

/// Find `git push` invocations that force, delete or rewrite refs.
pub fn force_push_hits(text: &str) -> Vec<ForceHit> {
    let mut hits = Vec::new();
    let mut joined = String::new();
    let mut start_line = 1usize;
    let mut joined_lines = 0usize;

    for (index, physical) in text.lines().enumerate() {
        let line_no = index + 1;
        if joined.is_empty() {
            start_line = line_no;
            joined_lines = 0;
        }
        let line = physical.trim_end();
        let continues = line.ends_with('\\');
        let piece = if continues {
            &line[..line.len() - 1]
        } else {
            line
        };
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(piece);
        joined_lines += 1;
        let too_long = joined.chars().count() >= MAX_LINE_CHARS;
        if continues && joined_lines < MAX_JOINED_LINES && !too_long {
            continue;
        }
        analyze(&joined, start_line, &mut hits);
        joined.clear();
    }
    if !joined.is_empty() {
        analyze(&joined, start_line, &mut hits);
    }
    hits
}

fn analyze(line: &str, line_no: usize, out: &mut Vec<ForceHit>) {
    let text: String = line.chars().take(MAX_LINE_CHARS).collect();
    for command in commands(&text) {
        for (index, token) in command.iter().enumerate() {
            if is_git_token(token) {
                if let Some(form) = push_force_form(&command[index + 1..]) {
                    out.push(ForceHit {
                        line: line_no,
                        form,
                        text: text.trim().to_string(),
                    });
                    break;
                }
            }
        }
    }
}

/// Split one line into simple commands. Shell separators end a command so that
/// `git push origin main || echo --force` is not mistaken for a forced push.
/// Quoted strings are *not* kept together: `sh -c "git push --force"` and
/// `node -e "...exec('git push -f')"` are recognized because their text still
/// tokenizes into `git`, `push`, `-f`.
fn commands(line: &str) -> Vec<Vec<String>> {
    let mut commands: Vec<Vec<String>> = Vec::new();
    let mut current: Vec<String> = Vec::new();
    for raw in line.split_whitespace() {
        let mut piece = String::new();
        for ch in raw.chars() {
            if matches!(ch, ';' | '&' | '|') {
                if !piece.is_empty() {
                    current.push(normalize(&piece));
                    piece.clear();
                }
                if !current.is_empty() {
                    commands.push(std::mem::take(&mut current));
                }
            } else {
                piece.push(ch);
            }
        }
        if !piece.is_empty() {
            current.push(normalize(&piece));
        }
    }
    if !current.is_empty() {
        commands.push(current);
    }
    commands.retain(|c| !c.is_empty());
    commands
}

/// Drop the quoting and bracketing that wraps a token inside a shell, JSON or
/// JavaScript string, so `"--force"`, `-f')` and `"+main"` compare cleanly.
fn normalize(token: &str) -> String {
    token
        .trim_matches(|c: char| {
            matches!(
                c,
                '"' | '\'' | '`' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | '\\'
            )
        })
        .to_string()
}

/// Is this token the start of a `git` invocation? Accepts `git`, `git.exe` and
/// the tail of a quoted or concatenated form such as `exec('git`.
fn is_git_token(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    for suffix in ["git.exe", "git.cmd", "git.bat", "git"] {
        if let Some(stem) = lower.strip_suffix(suffix) {
            return match stem.chars().next_back() {
                None => true,
                Some(c) => !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')),
            };
        }
    }
    false
}

/// If `args` is `push` plus a forcing form, name the form.
fn push_force_form(args: &[String]) -> Option<&'static str> {
    let mut index = 0;
    // Skip `git` global options; `-C <dir>` and `-c <k=v>` take a value.
    while index < args.len() {
        let arg = &args[index];
        if matches!(
            arg.as_str(),
            "-C" | "-c" | "--git-dir" | "--work-tree" | "--namespace"
        ) {
            index += 2;
            continue;
        }
        if arg.starts_with('-') {
            index += 1;
            continue;
        }
        break;
    }
    let subcommand = args.get(index)?;
    if !subcommand.eq_ignore_ascii_case("push") {
        return None;
    }
    for arg in &args[index + 1..] {
        // `--force`, `--force-with-lease`, `--force-with-lease=<ref>` and
        // `--force-if-includes` all begin with `--force`.
        if arg.starts_with("--force") {
            return Some("--force");
        }
        if arg == "-f" {
            return Some("-f");
        }
        if arg == "--mirror" {
            return Some("--mirror");
        }
        if arg == "--delete" || arg == "-d" {
            return Some("--delete");
        }
        // `+refspec` forces one update; `:refspec` deletes it.
        if arg.len() > 1 && arg.starts_with('+') {
            return Some("+refspec");
        }
        if arg.len() > 1 && arg.starts_with(':') {
            return Some(":refspec");
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_every_force_form() {
        for text in [
            "git push --force",
            "git push --force origin main",
            "git push --force-with-lease origin main",
            "git push -f origin main",
            "git push --mirror origin",
            "git push --delete origin old",
            "git push -d origin old",
            "git push origin +main",
            "git push origin :stale-branch",
            "git push +refs/heads/main:refs/heads/main",
        ] {
            let hits = force_push_hits(text);
            assert_eq!(hits.len(), 1, "{text}");
            assert_eq!(hits[0].line, 1, "{text}");
        }
    }

    #[test]
    fn detects_wrapped_aliases() {
        for text in [
            "sh -c \"git push --force origin main\"",
            "bash -lc 'git push -f origin main'",
            "npx --no-install git push --force",
            "node -e \"require('child_process').execSync('git push -f origin main')\"",
            "sh -c \"git -C repo push --force\"",
        ] {
            assert_eq!(force_push_hits(text).len(), 1, "{text}");
        }
    }

    #[test]
    fn joins_continuations() {
        let hits = force_push_hits("git push \\\n  --force origin main");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 1);
    }

    #[test]
    fn ignores_benign_commands() {
        for text in [
            "git push origin main",
            "git push",
            "git pull --force",
            "git fetch --force origin",
            "npm run push",
            "echo git push is guarded",
            "git status",
            "git push origin main || echo --force",
            "prettier --write .",
        ] {
            assert!(force_push_hits(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn reports_line_numbers() {
        let hits = force_push_hits("echo one\n# note\ngit push --force origin main\n");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line, 3);
        assert_eq!(hits[0].form, "--force");
    }

    #[test]
    fn bounds_a_hostile_line() {
        let long = format!("git push --force {}", "x".repeat(100_000));
        let hits = force_push_hits(&long);
        assert_eq!(hits.len(), 1);
        assert!(hits[0].text.chars().count() <= MAX_LINE_CHARS);
    }
}
