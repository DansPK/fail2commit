import * as fs from "node:fs";
import * as nodePath from "node:path";

export interface ResolveEnv {
  platform: NodeJS.Platform;
  env: Record<string, string | undefined>;
  home: string;
  /** Open workspace folder paths. */
  folders: string[];
  exists?: (p: string) => boolean;
  realpath?: (p: string) => string;
}

export type Resolved = { path: string } | { error: string };

const flavor = (platform: NodeJS.Platform) => (platform === "win32" ? nodePath.win32 : nodePath.posix);

/** Only the machine/user value counts; a workspace or folder value is never trusted. */
export function trustedSetting(inspect?: { globalValue?: string }): string | undefined {
  const v = inspect?.globalValue;
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

export function isInside(candidate: string, folders: string[], platform: NodeJS.Platform, realpath?: (p: string) => string): boolean {
  const p = flavor(platform);
  const norm = (x: string) => {
    let r = x;
    try { r = realpath ? realpath(x) : x; } catch { /* nonexistent: compare lexically */ }
    r = p.resolve(r);
    return platform === "win32" ? r.toLowerCase() : r;
  };
  const c = norm(candidate);
  return folders.some((f) => {
    const rel = p.relative(norm(f), c);
    return rel === "" || (!rel.startsWith("..") && !p.isAbsolute(rel));
  });
}

export function resolveCli(configured: string | undefined, e: ResolveEnv): Resolved {
  const p = flavor(e.platform);
  const exists = e.exists ?? ((x) => fs.existsSync(x) && fs.statSync(x).isFile());
  const realpath = e.realpath ?? ((x) => fs.realpathSync(x));
  const bad = (c: string) => isInside(c, e.folders, e.platform, realpath);
  if (configured) {
    if (!p.isAbsolute(configured)) return { error: "fail2commit.cliPath must be an absolute path" };
    if (bad(configured)) return { error: "fail2commit.cliPath points inside a workspace folder and was rejected" };
    return exists(configured) ? { path: configured } : { error: `fail2commit.cliPath does not exist: ${configured}` };
  }
  const exe = e.platform === "win32" ? "fail2commit.exe" : "fail2commit";
  const known = e.platform === "win32"
    ? [p.join(e.env.LOCALAPPDATA ?? p.join(e.home, "AppData", "Local"), "Programs", "fail2commit", exe)]
    : [p.join(e.home, ".local", "bin", exe), p.join("/usr/bin", exe), p.join("/usr/local/bin", exe)];
  const onPath = (e.env.PATH ?? e.env.Path ?? "").split(e.platform === "win32" ? ";" : ":")
    .filter((d) => d && p.isAbsolute(d)).map((d) => p.join(d, exe));
  for (const c of [...known, ...onPath]) {
    if (exists(c) && !bad(c)) return { path: c };
  }
  return { error: "fail2commit CLI not found outside the workspace; set the machine-scoped fail2commit.cliPath" };
}
