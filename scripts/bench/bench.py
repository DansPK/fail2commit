#!/usr/bin/env python3
"""fail2commit resource benchmark driver (T-012, NFR-012, SPEC-012, TC-012).

Called by run.ps1 / run.sh after they build release binaries. Uses only
disposable FAIL2COMMIT_HOME dirs and repos under a temp dir, and never the
network: OSV lookups go to a loopback stub (osv_stub.py).

  bench.py measure --bin-dir DIR --out FILE [--runs N]
"""
import argparse, json, os, platform, random, re, shutil, statistics
import subprocess, sys, tempfile, time

EXE = ".exe" if os.name == "nt" else ""
HERE = os.path.dirname(os.path.abspath(__file__))
WORDS = ("alpha bravo charlie delta echo foxtrot golf hotel india juliet kilo lima "
         "mike november oscar papa quebec romeo sierra tango uniform victor whiskey "
         "xray yankee zulu").split()


def pctl(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1) + 0.4999)))]


def stats(xs):
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 1),
            "p95_ms": round(pctl(xs, 95), 1), "min_ms": round(min(xs), 1),
            "raw_ms": [round(x, 1) for x in xs]}


def timed(cmd, **kw):
    t = time.perf_counter()
    p = subprocess.run(cmd, capture_output=True, **kw)
    return (time.perf_counter() - t) * 1000, p


def dir_bytes(path):
    total = files = 0
    for root, _, names in os.walk(path):
        for n in names:
            files += 1
            total += os.path.getsize(os.path.join(root, n))
    return total, files


def tool(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout.strip().splitlines()[0]
    except Exception as e:  # noqa: BLE001 - recorded as evidence
        return f"unavailable ({e.__class__.__name__})"


def make_repo(root, mb, commits):
    """Disposable repo of ~mb MB of low-entropy text in `commits` commits."""
    os.makedirs(root)
    git = lambda *a: subprocess.run(["git", "-C", root, *a], check=True, capture_output=True)  # noqa: E731
    git("init", "-q", "-b", "main")
    git("config", "user.email", "bench@example.invalid")
    git("config", "user.name", "bench")
    git("config", "commit.gpgsign", "false")
    rng = random.Random(12)
    per_commit = mb * 1024 * 1024 // commits
    file_size = 64 * 1024
    for c in range(commits):
        d = os.path.join(root, f"d{c}")
        os.makedirs(d)
        for f in range(max(1, per_commit // file_size)):
            lines, size = [], 0
            while size < file_size:
                ln = " ".join(rng.choice(WORDS) for _ in range(12))
                lines.append(ln)
                size += len(ln) + 1
            with open(os.path.join(d, f"f{f}.txt"), "w", newline="\n") as fh:
                fh.write("\n".join(lines))
        git("add", "-A")
        git("commit", "-q", "-m", f"c{c}")
    return dir_bytes(os.path.join(root))[0]


class Home:
    def __init__(self, tmp, name, osv_url=None, limits=None):
        self.path = os.path.join(tmp, name)
        os.makedirs(os.path.join(self.path, "config"))
        lines = []
        if osv_url:
            lines += ["[advisories]", f'osv_url = "{osv_url}"']
        if limits:
            lines += ["[limits]"] + [f"{k} = {v}" for k, v in limits.items()]
        with open(os.path.join(self.path, "config", "settings.toml"), "w") as f:
            f.write("\n".join(lines) + "\n")
        self.env = dict(os.environ, FAIL2COMMIT_HOME=self.path)
        self.env.pop("F2C_BIN", None)


def start_stub(tmp):
    pf = os.path.join(tmp, "stub.port")
    p = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "osv_stub.py"), pf])
    for _ in range(100):
        if os.path.exists(pf) and os.path.getsize(pf):
            return p, f"http://127.0.0.1:{open(pf).read().strip()}"
        time.sleep(0.05)
    p.kill()
    raise SystemExit("osv stub did not start")


def stub_hits(url):
    import urllib.request
    return json.load(urllib.request.urlopen(url + "/__hits"))["hits"]


def measure(a):
    f2c = os.path.join(a.bin_dir, "fail2commit" + EXE)
    tray = os.path.join(a.bin_dir, "fail2commit-tray" + EXE)
    out = {"host": {"os": platform.platform(), "machine": platform.machine(),
                    "cpu": platform.processor() or "", "cpus": os.cpu_count(),
                    "python": sys.version.split()[0]},
           "tools": {"rustc": tool(["rustc", "--version"]), "git": tool(["git", "--version"])},
           "binaries": {}, "startup": {}, "scan": {}, "advisory": {}, "sandbox": {}}
    if os.name == "nt":
        out["host"]["ram_gb"] = tool(["powershell", "-NoProfile", "-Command",
                                      "[math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1)"])
        out["host"]["cpu"] = tool(["powershell", "-NoProfile", "-Command",
                                   "(Get-CimInstance Win32_Processor).Name"])
    else:
        out["host"]["ram_gb"] = tool(["sh", "-c", "awk '/MemTotal/{printf \"%.1f\", $2/1048576}' /proc/meminfo"])
    out["binaries"]["fail2commit_bytes"] = os.path.getsize(f2c)
    if os.path.exists(tray):
        out["binaries"]["fail2commit_tray_bytes"] = os.path.getsize(tray)
    out["tools"]["fail2commit"] = tool([f2c, "--version"])

    with tempfile.TemporaryDirectory(prefix="f2c-bench-") as tmp:
        # CLI startup: cold = first launch of this binary with a fresh home
        # (OS file cache is not flushed; no admin needed), warm = the next N.
        for name, args in (("version", ["--version"]), ("status", ["status"])):
            h = Home(tmp, "home-" + name)
            cold, p = timed([f2c, *args], env=h.env)
            warm = [timed([f2c, *args], env=h.env)[0] for _ in range(a.runs)]
            out["startup"][name] = {"cold_ms": round(cold, 1), "exit": p.returncode, "warm": stats(warm)}

        # Guarded secret-scan on generated disposable repos (no remote: the
        # scan covers every commit). Cold = first run, warm = repeats.
        for mb in a.repo_mb:
            repo = os.path.join(tmp, f"repo{mb}")
            size = make_repo(repo, mb, 10)
            h = Home(tmp, f"home-scan{mb}")
            cold, p = timed([f2c, "--json", "secret-scan"], cwd=repo, env=h.env)
            warm = [timed([f2c, "--json", "secret-scan"], cwd=repo, env=h.env)[0] for _ in range(max(3, a.runs // 3))]
            body = {}
            try:
                body = json.loads(p.stdout)
            except ValueError:
                pass
            out["scan"][f"secret_scan_{mb}MB"] = {
                "fixture_bytes": size, "commits": 10, "cold_ms": round(cold, 1), "exit": p.returncode,
                "code": body.get("code"), "warm": stats(warm)}

        # Advisory scan against the loopback stub: empty vs warm cache.
        stub, url = start_stub(tmp)
        try:
            for n in a.lookups:
                pk = [f"npm:pkg-{i}@1.0.0" for i in range(n)]
                h = Home(tmp, f"home-osv{n}", osv_url=url)
                before = stub_hits(url)
                cold, p = timed([f2c, "--json", "scan", *pk], env=h.env)
                mid = stub_hits(url)
                warm = [timed([f2c, "--json", "scan", *pk], env=h.env)[0] for _ in range(max(3, a.runs // 3))]
                after = stub_hits(url)
                cache = os.path.join(h.path, "cache")
                size, files = dir_bytes(cache)
                out["advisory"][f"lookups_{n}"] = {
                    "cold_empty_cache_ms": round(cold, 1), "cold_exit": p.returncode,
                    "cold_stub_requests": mid - before, "warm": stats(warm),
                    "warm_stub_requests": after - mid, "cache_bytes": size, "cache_files": files}
        finally:
            stub.kill()

        # Native build through the sandbox. Pending unless a backend works.
        h = Home(tmp, "home-sandbox")
        probe = subprocess.run([f2c, "--json", "sandbox", "status"], capture_output=True, text=True, env=h.env)
        try:
            pd = json.loads(probe.stdout)["data"]
        except (ValueError, KeyError):
            pd = {"available": False, "backend": "?", "detail": probe.stdout[:200]}
        out["sandbox"]["backend"] = pd.get("backend")
        out["sandbox"]["detail"] = pd.get("detail")
        if not pd.get("available"):
            out["sandbox"]["native_build"] = "PENDING: sandbox backend unavailable on this host"
        else:
            out["sandbox"]["native_build"] = native_build(a, f2c, tmp, h)
    with open(a.out, "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out, indent=2))


def native_build(a, f2c, tmp, h):
    """Peak memory is measured inside the sandbox: getrusage through bwrap
    undercounts (bwrap reaps its children). The CLI cannot bind a staged gcc
    sysroot, so this needs a root-owned /usr/bin/gcc (rust:1 container)."""
    if not (os.path.exists("/usr/bin/gcc") and os.stat("/usr/bin/gcc").st_uid == 0 and os.path.exists("/usr/bin/python3")):
        return "PENDING: needs a root-owned /usr/bin/gcc and python3 (run scripts/bench/privileged.sh in rust:1)"
    src = os.path.join(HERE, "..", "..", "tests", "fixtures", "sandbox", "native", "hello.c")
    inp = os.path.join(tmp, "build-in")
    os.makedirs(inp)
    shutil.copy(src, os.path.join(inp, "hello.c"))
    script = ("import resource,subprocess,time;t=time.time();"
              "r=subprocess.run(['gcc','-O2','-o','hello','hello.c']);"
              "print('PEAK_KB=%d BUILD_S=%.2f'%(resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,time.time()-t));"
              "raise SystemExit(r.returncode)")
    runs = []
    for i in range(5):
        cmd = [f2c, "--json", "run", "--input", inp, "--export", "hello", "--to", os.path.join(tmp, f"out{i}"),
               "--", "/usr/bin/python3", "-I", "-c", script]
        t = time.perf_counter()
        p = subprocess.run(cmd, capture_output=True, text=True, env=h.env)
        wall = time.perf_counter() - t
        try:
            d = json.loads(p.stdout)["data"]
            m = re.search(r"PEAK_KB=(\d+) BUILD_S=([\d.]+)", d["stdout"])
            runs.append({"exit": d["exit_code"], "peak_single_process_kb": int(m.group(1)),
                         "gcc_s": float(m.group(2)), "wall_s": round(wall, 2), "exported": bool(d["exported"])})
        except (ValueError, KeyError, AttributeError):
            return f"FAILED to measure: {p.stdout[-300:]} {p.stderr[-300:]}"
    return {"note": "peak = largest single process in the gcc tree (cc1/as/ld), getrusage RUSAGE_CHILDREN "
                    "inside the sandbox; fixture tests/fixtures/sandbox/native/hello.c, gcc -O2", "runs": runs}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("measure")
    m.add_argument("--bin-dir", required=True)
    m.add_argument("--out", required=True)
    m.add_argument("--runs", type=int, default=20)
    m.add_argument("--repo-mb", type=int, nargs="*", default=[8, 64])
    m.add_argument("--lookups", type=int, nargs="*", default=[50, 200, 500])
    a = ap.parse_args()
    measure(a)
