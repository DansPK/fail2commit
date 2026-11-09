// Display sanitizer for untrusted text (W1-004, W1-005, R1-004). Mirrors
// crates/fail2commit-core/src/redact.rs (`redact_url_credentials`,
// `is_invisible_or_bidi`) and approval/console.rs `sanitize`: redact URL
// userinfo up to the last `@` of the authority, then escape control,
// format (Cf), separator and tag characters so names cannot leak secrets,
// hide differences or reorder text. Ranges are numeric so this source file
// stays pure ASCII.
const UNSAFE: ReadonlyArray<readonly [number, number]> = [
  [0x00, 0x1f], [0x7f, 0x9f], [0xad, 0xad], [0x61c, 0x61c], [0x180e, 0x180e],
  [0x200b, 0x200f], [0x2028, 0x202e], [0x2060, 0x206f], [0xfeff, 0xfeff],
  [0xfff9, 0xfffb], [0xe0000, 0xe007f],
];

const unsafeCp = (cp: number) => UNSAFE.some(([lo, hi]) => cp >= lo && cp <= hi);

const USERINFO = /([a-z][a-z0-9+.-]*:\/\/)[^/ \t\r\n]*@/gi;

export function sanitize(text: string): string {
  return Array.from(text.replace(USERINFO, "$1***@"), (ch) => {
    const cp = ch.codePointAt(0)!;
    return unsafeCp(cp) ? `\\u{${cp.toString(16)}}` : ch;
  }).join("");
}
