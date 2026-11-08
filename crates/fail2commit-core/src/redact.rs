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
/// Userinfo runs to the last `@` before the authority ends (R1-004), so a
/// password containing `@` or non-ASCII spaces is fully redacted.
pub fn redact_url_credentials(text: &str) -> String {
    let re = regex::Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)[^/ \t\r\n]*@").expect("static regex");
    re.replace_all(text, "${1}***@").into_owned()
}

/// Characters that are invisible or reorder text: Unicode format (Cf),
/// line/paragraph separators and tag characters (R1-004, W1-005).
pub fn is_invisible_or_bidi(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00ad}'
                | '\u{061c}'
                | '\u{180e}'
                | '\u{200b}'..='\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2060}'..='\u{206f}'
                | '\u{feff}'
                | '\u{fff9}'..='\u{fffb}'
                | '\u{e0000}'..='\u{e007f}'
        )
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
        let pw = ["p", "@", "ss\u{a0}x"].concat();
        let out = redact_url_credentials(&format!("https://user:{pw}@host.test/r and more"));
        assert_eq!(out, "https://***@host.test/r and more");
        assert_eq!(
            redact_url_credentials("see https://host.test/a@b"),
            "see https://host.test/a@b"
        );
    }

    #[test]
    fn flags_invisible_and_bidi() {
        for c in [
            '\u{061c}',
            '\u{2060}',
            '\u{2064}',
            '\u{feff}',
            '\u{2028}',
            '\u{2029}',
            '\u{00ad}',
            '\u{e0041}',
            '\u{202e}',
            '\u{1b}',
        ] {
            assert!(is_invisible_or_bidi(c), "{:x}", c as u32);
        }
        for c in ['a', ' ', '/', '\u{e9}'] {
            assert!(!is_invisible_or_bidi(c));
        }
    }
}
