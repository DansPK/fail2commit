// Display sanitizer for untrusted text (W1-004, W1-005). Mirrors the core
// terminal renderer (crates/fail2commit-core/src/approval/console.rs):
// strip URL credentials, then escape control, zero-width and bidi
// characters so ref or package names cannot leak secrets or reorder text.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g;

export function sanitize(text: string): string {
  return text
    .replace(/([a-z][a-z0-9+.-]*:\/\/)[^/\s@]+@/gi, "$1***@")
    .replace(UNSAFE, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
}
