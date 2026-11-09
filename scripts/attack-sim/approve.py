#!/usr/bin/env python3
"""Play the VS Code client over `fail2commit api`: send one request, answer
every approval request with <decision> (approve_once | cancel | run_on_host_once).

usage: approve.py <cwd> <decision> <argv...>     prints a JSON summary line
"""
import json, subprocess, sys

cwd, decision, argv = sys.argv[1], sys.argv[2], sys.argv[3:]
p = subprocess.Popen(["fail2commit", "api"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, text=True, cwd=cwd)
p.stdin.write(json.dumps({"version": 1, "id": "flow-1", "argv": argv, "cwd": cwd}) + "\n")
p.stdin.flush()
asked, result = [], None
for line in p.stdout:
    m = json.loads(line)
    if m["type"] == "approval_request":
        asked.append({"kind": m["kind"], "summary": m["summary"],
                      "findings": [f["kind"] + ":" + f.get("evidence", "")[:80] for f in m.get("findings", [])],
                      "allowed": m["allowed"]})
        p.stdin.write(json.dumps({"type": "approval_response", "version": 1, "request_id": m["request_id"],
                                  "nonce": m["nonce"], "digest": m["digest"], "decision": decision,
                                  "password": None}) + "\n")
        p.stdin.flush()
    elif m["type"] == "result":
        result = m
p.stdin.close()
p.wait(timeout=600)
print(json.dumps({"exit": p.returncode, "code": result and result["code"],
                  "message": result and result["message"][:300], "asked": asked}))
