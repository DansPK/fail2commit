//! Explicit force intent on a `git push` command line (the shim's view).
//!
//! This only recognises flags and `+`/`:` refspec prefixes. Resolving what a
//! refspec means (wildcards, defaults) is left to Git; the pre-push hook
//! checks the resulting tuples.

/// Index of the git subcommand, skipping global options.
pub fn subcommand_index(args: &[String]) -> Option<usize> {
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if matches!(
            a,
            "-C" | "-c"
                | "--git-dir"
                | "--work-tree"
                | "--namespace"
                | "--super-prefix"
                | "--config-env"
                | "--attr-source"
        ) {
            i += 2;
        } else if a.starts_with('-') {
            i += 1;
        } else {
            return Some(i);
        }
    }
    None
}

/// `-c key=value` pairs from the global options (before the subcommand).
pub fn config_overrides(globals: &[String]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < globals.len() {
        if globals[i] == "-c" {
            if let Some(kv) = globals.get(i + 1) {
                let (k, v) = kv.split_once('=').unwrap_or((kv.as_str(), ""));
                out.push((k.to_ascii_lowercase(), v.to_string()));
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// What the push command line asks for, in the user's own words.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PushIntent {
    pub reasons: Vec<String>,
    /// Explicit refspecs were given (they override `remote.<n>.push`).
    pub explicit_refspecs: bool,
    /// The repository argument, if any.
    pub repository: Option<String>,
}

/// Analyse the arguments after `push`.
pub fn push_intent(args: &[String]) -> PushIntent {
    let mut p = PushIntent::default();
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    let mut rest_positional = false;
    while i < args.len() {
        let a = args[i].as_str();
        i += 1;
        if rest_positional || !a.starts_with('-') || a == "-" {
            positional.push(a);
            continue;
        }
        if a == "--" {
            rest_positional = true;
            continue;
        }
        if let Some(long) = a.strip_prefix("--") {
            let (name, _) = long.split_once('=').unwrap_or((long, ""));
            match name {
                "force" | "mirror" | "delete" | "prune" | "force-if-includes" => {
                    p.reasons.push(format!("--{name}"))
                }
                "force-with-lease" => p.reasons.push(a.to_string()),
                // options that take their value as the next argument
                "repo" | "receive-pack" | "exec" | "push-option" if !long.contains('=') => i += 1,
                _ => {}
            }
        } else {
            // short cluster: -fu, -d, -ofoo (value), -o foo
            let cluster = &a[1..];
            for (n, ch) in cluster.char_indices() {
                match ch {
                    'f' => p.reasons.push("-f".into()),
                    'd' => p.reasons.push("-d".into()),
                    'o' => {
                        if n + 1 == cluster.len() {
                            i += 1;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
    p.repository = positional.first().map(|s| s.to_string());
    for spec in positional.iter().skip(1) {
        p.explicit_refspecs = true;
        if spec.starts_with('+') {
            p.reasons.push(format!("forced refspec {spec}"));
        } else if spec.starts_with(':') && spec.len() > 1 {
            p.reasons.push(format!("deleting refspec {spec}"));
        }
    }
    p.reasons.dedup();
    p
}

/// Whether a configured `remote.<name>.push` value forces. `value` may be
/// a refspec such as `+refs/heads/*:refs/heads/*`.
pub fn is_forced_refspec(value: &str) -> bool {
    value.trim_start().starts_with('+')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn finds_subcommand_past_globals() {
        assert_eq!(
            subcommand_index(&a(&["-C", "x", "-c", "a=b", "push"])),
            Some(4)
        );
        assert_eq!(subcommand_index(&a(&["--no-pager", "status"])), Some(1));
        assert_eq!(subcommand_index(&a(&["--version"])), None);
    }

    #[test]
    fn force_forms() {
        for args in [
            vec!["--force"],
            vec!["-f"],
            vec!["-uf", "origin"],
            vec!["--force-with-lease"],
            vec!["--force-with-lease=main:abc"],
            vec!["--force-if-includes"],
            vec!["--mirror"],
            vec!["--delete", "origin", "x"],
            vec!["-d", "origin", "x"],
            vec!["origin", "+main"],
            vec!["origin", "+refs/heads/*:refs/heads/*"],
            vec!["origin", ":old"],
        ] {
            assert!(!push_intent(&a(&args)).reasons.is_empty(), "{args:?}");
        }
        for args in [
            vec!["origin", "main"],
            vec!["-u", "origin", "main"],
            vec!["-o", "-f", "origin"],
            vec!["--push-option", "-f", "origin"],
            vec!["--tags"],
            vec!["origin", "--", "-f"],
        ] {
            assert!(push_intent(&a(&args)).reasons.is_empty(), "{args:?}");
        }
    }

    #[test]
    fn repository_and_refspecs() {
        let p = push_intent(&a(&["-u", "origin", "main"]));
        assert_eq!(p.repository.as_deref(), Some("origin"));
        assert!(p.explicit_refspecs);
        assert!(!push_intent(&a(&["origin"])).explicit_refspecs);
    }
}
