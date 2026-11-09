import * as vscode from "vscode";
import { execFile } from "node:child_process";
import * as os from "node:os";
import { ApprovalRequest, Decision, Finding, Response, runApi } from "./client";
import { resolveCli, trustedSetting } from "./cli";
import { sanitize } from "./sanitize";

let channel: vscode.OutputChannel;
let lastFindings: Finding[] = [];

const fmt = (f: Finding) =>
  sanitize(`[${f.action}] ${f.kind} (${f.source})${f.target ? ` ${f.target}` : ""}${f.location ? ` @ ${f.location}` : ""}: ${f.evidence}`);

function git(cwd: string, args: string[]): Promise<string[]> {
  return new Promise((resolve) =>
    execFile("git", args, { cwd, shell: false, windowsHide: true }, (err, out) =>
      resolve(err ? [] : out.split(/\r?\n/).filter(Boolean))));
}

async function approve(req: ApprovalRequest) {
  const labels: Record<string, Decision> = { "Approve once": "approve_once", "Run on host once": "run_on_host_once" };
  const buttons = Object.keys(labels).filter((l) => req.allowed.includes(labels[l]));
  const detail = [...(req.details ?? []).map(sanitize), ...(req.findings ?? []).map(fmt)].join("\n");
  // The modal's built-in Cancel is the default; dismissing returns undefined.
  const pick = await vscode.window.showWarningMessage(sanitize(req.summary), { modal: true, detail }, ...buttons);
  if (!pick) return { decision: "cancel" as Decision };
  let password: string | undefined;
  if (req.password_required) {
    password = await vscode.window.showInputBox({ title: "fail2commit password", prompt: "Force-push password", password: true, ignoreFocusOut: true });
    if (password === undefined) return { decision: "cancel" as Decision };
  }
  return { decision: labels[pick], password };
}

async function run(argv: string[], cwd: string): Promise<void> {
  if (!vscode.workspace.isTrusted) {
    vscode.window.showErrorMessage("fail2commit needs a trusted workspace.");
    return;
  }
  const folders = (vscode.workspace.workspaceFolders ?? []).map((f) => f.uri.fsPath);
  const configured = trustedSetting(vscode.workspace.getConfiguration("fail2commit").inspect<string>("cliPath"));
  const cli = resolveCli(configured, { platform: process.platform, env: process.env, home: os.homedir(), folders });
  if ("error" in cli) {
    vscode.window.showErrorMessage(cli.error);
    return;
  }
  channel.appendLine(sanitize(`> fail2commit ${argv.join(" ")}`));
  try {
    const res: Response = await vscode.window.withProgress(
      { location: vscode.ProgressLocation.Notification, title: `fail2commit ${argv[0]}` },
      (p) => runApi({
        cli: cli.path, argv, cwd,
        ui: { approve, progress: (m) => { p.report({ message: sanitize(m) }); channel.appendLine(sanitize(m)); } },
      }));
    lastFindings = res.findings;
    channel.appendLine(sanitize(`${res.code}: ${res.message}`));
    res.findings.forEach((f) => channel.appendLine("  " + fmt(f)));
    const show = res.code === "ok" ? vscode.window.showInformationMessage : vscode.window.showWarningMessage;
    show(sanitize(`fail2commit: ${res.message || res.code}`));
  } catch (e) {
    channel.appendLine(sanitize(`error: ${(e as Error).message}`));
    vscode.window.showErrorMessage(sanitize(`fail2commit: ${(e as Error).message}`));
  }
}

// Labels are sanitized for display; the raw value is what gets passed on (R1-006).
const pick = async (items: string[], placeHolder: string) =>
  (await vscode.window.showQuickPick(items.map((v) => ({ label: sanitize(v), value: v })), { placeHolder }))?.value;

export function activate(ctx: vscode.ExtensionContext) {
  channel = vscode.window.createOutputChannel("fail2commit");
  const cwd = () => vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
  const reg = (name: string, fn: (cwd: string) => Promise<string[] | undefined>) =>
    ctx.subscriptions.push(vscode.commands.registerCommand(`fail2commit.${name}`, async () => {
      const dir = cwd();
      if (!dir) return vscode.window.showErrorMessage("Open a folder first.");
      const argv = await fn(dir);
      if (argv) await run(argv, dir);
    }));

  reg("push", async (dir) => {
    const remote = await pick(await git(dir, ["remote"]), "Remote");
    if (!remote) return;
    const branch = await pick(await git(dir, ["for-each-ref", "--format=%(refname:short)", "refs/heads"]), "Branch");
    return branch ? ["git", "push", remote, branch] : undefined;
  });
  reg("npm", async () => {
    const sub = await pick(["install", "ci"], "npm command");
    return sub ? ["npm", sub] : undefined;
  });
  reg("pip", async () => {
    const dflt = vscode.workspace.getConfiguration("python").get<string>("defaultInterpreterPath") ?? "";
    const py = await vscode.window.showInputBox({ prompt: "Python interpreter", value: dflt });
    if (!py) return;
    const pkgs = await vscode.window.showInputBox({ prompt: "Packages (space separated)" });
    return pkgs?.trim() ? ["pip", "install", "--python", py, ...pkgs.trim().split(/\s+/)] : undefined;
  });
  reg("status", async () => ["status"]);
  reg("sandboxOn", async () => ["sandbox", "on"]);
  reg("sandboxOff", async () => ["sandbox", "off"]);
  ctx.subscriptions.push(vscode.commands.registerCommand("fail2commit.showFindings", () => {
    channel.clear();
    channel.appendLine(lastFindings.length ? lastFindings.map(fmt).join("\n") : "No findings.");
    channel.show();
  }), channel);
}

export function deactivate() {}
