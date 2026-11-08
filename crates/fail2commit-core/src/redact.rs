//! Redaction helpers (CHORE-001, frozen). Never print a matched value.

/// Placeholder for a secret value: reveals only its length class.
pub fn redact(value: &str) -> String {
    format!("[redacted {} chars]", value.chars().count())
}

/// Replace every `needle` occurrence in `line` with a redaction marker.
pub fn redact_in(line: &str, needle: &str) -> String {
    if needle.is_empty() {
        return line.to_string();
    }
    line.replace(needle, &redact(needle))
}

/// Strip userinfo from URLs (`https://user:token@host` -> `https://***@host`).
pub fn redact_url_credentials(text: &str) -> String {
    let re = regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/\s@]+@").expect("static regex");
    re.replace_all(text, "${1}***@").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_values() {
        let s = "AKIA0000SYNTHETIC0000";
        let out = redact_in(&format!("key={s}"), s);
        assert!(!out.contains(s));
        assert_eq!(
            redact_url_credentials("git push https://u:tok@example.test/r.git"),
            "git push https://***@example.test/r.git"
        );
    }
}
