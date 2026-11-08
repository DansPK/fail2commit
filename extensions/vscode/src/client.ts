import { spawn as nodeSpawn, SpawnOptions } from "node:child_process";
import { randomUUID } from "node:crypto";

export const MAX_MESSAGE_BYTES = 256 * 1024;
export const PROTOCOL_VERSION = 1;

export type Decision = "cancel" | "approve_once" | "run_on_host_once";
export interface Finding { kind: string; action: string; source: string; evidence: string; target?: string; location?: string; advisory_id?: string }
export interface Response { version: number; id?: string; code: string; message: string; findings: Finding[]; tool_exit?: number; data?: unknown }
export interface ApprovalRequest {
  version: number; request_id: string; nonce: string; digest: string; session: string; kind: string;
  summary: string; details?: string[]; findings?: Finding[]; expires_at: number; password_required?: boolean; allowed: Decision[];
}
export interface Ui {
  progress(message: string): void;
  approve(req: ApprovalRequest): Promise<{ decision: Decision; password?: string } | undefined>;
}
export type SpawnFn = (cmd: string, args: string[], opts: SpawnOptions) => ReturnType<typeof nodeSpawn>;

/** Splits stdout into lines, failing once any line exceeds MAX_MESSAGE_BYTES. */
export class LineSplitter {
  private buf = Buffer.alloc(0);
  push(chunk: Buffer): string[] {
    this.buf = Buffer.concat([this.buf, chunk]);
    const out: string[] = [];
    let i: number;
    while ((i = this.buf.indexOf(10)) >= 0) {
      if (i > MAX_MESSAGE_BYTES) throw new Error("message exceeds MAX_MESSAGE_BYTES");
      out.push(this.buf.subarray(0, i).toString("utf8").trim());
      this.buf = this.buf.subarray(i + 1);
    }
    if (this.buf.length > MAX_MESSAGE_BYTES) throw new Error("message exceeds MAX_MESSAGE_BYTES");
    return out.filter((l) => l);
  }
}

export interface RunOptions {
  cli: string;
  argv: string[];
  cwd?: string;
  ui: Ui;
  spawnFn?: SpawnFn;
  env?: NodeJS.ProcessEnv;
}

export function runApi(o: RunOptions): Promise<Response> {
  return new Promise((resolve, reject) => {
    const id = randomUUID();
    // shell:false and an args array: nothing is ever interpolated.
    const child = (o.spawnFn ?? nodeSpawn)(o.cli, ["api"], {
      shell: false, windowsHide: true, cwd: o.cwd, env: o.env ?? process.env, stdio: ["pipe", "pipe", "pipe"],
    });
    const split = new LineSplitter();
    let result: Response | undefined;
    let failed = false;
    let stderr = "";
    let queue: Promise<void> = Promise.resolve();
    const fail = (e: Error) => {
      if (failed) return;
      failed = true;
      child.kill();
      reject(e);
    };
    // A dropped pipe makes the CLI fail closed (no approval received).
    child.stdin!.on("error", () => undefined);
    const send = (msg: object) => {
      const buf = Buffer.from(JSON.stringify(msg) + "\n", "utf8");
      child.stdin!.write(buf);
      buf.fill(0);
    };
    const handle = async (line: string) => {
      const msg = JSON.parse(line);
      if (msg.type === "progress") o.ui.progress(String(msg.message));
      else if (msg.type === "result") result = msg as Response;
      else if (msg.type === "approval_request") {
        const req = msg as ApprovalRequest;
        let ans: { decision: Decision; password?: string } | undefined;
        try { ans = await o.ui.approve(req); } catch { ans = undefined; }
        // Anything not offered, or a dismissed dialog, is Cancel.
        const decision: Decision = ans && req.allowed.includes(ans.decision) ? ans.decision : "cancel";
        const password = decision !== "cancel" && req.password_required ? ans?.password : undefined;
        send({
          type: "approval_response", version: PROTOCOL_VERSION, request_id: req.request_id,
          nonce: req.nonce, digest: req.digest, decision, ...(password !== undefined ? { password } : {}),
        });
        if (ans) ans.password = undefined;
      }
    };
    child.stdout!.on("data", (c: Buffer) => {
      try {
        for (const line of split.push(c)) queue = queue.then(() => handle(line)).catch(fail);
      } catch (e) { fail(e as Error); }
    });
    child.stderr!.on("data", (c: Buffer) => { if (stderr.length < 4096) stderr += c.toString("utf8").slice(0, 4096); });
    child.on("error", fail);
    child.on("close", (code) => {
      queue.then(() => {
        if (failed) return;
        if (result) resolve(result);
        else reject(new Error(`fail2commit exited (${code}) without a result${stderr ? `: ${stderr.trim()}` : ""}`));
      });
    });
    send({ version: PROTOCOL_VERSION, id, argv: o.argv, ...(o.cwd ? { cwd: o.cwd } : {}) });
  });
}
