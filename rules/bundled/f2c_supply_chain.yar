// fail2commit bundled YARA rules (FR-019). Written for this project from the
// CR-017 supply-chain patterns; no third-party rule sets. Apache-2.0, like the
// rest of the repository. A match is a `yara_match` warning that needs
// approval, never a denial: these are heuristics.
//
// Each rule needs `meta: description`, which is shown in the finding.

rule hidden_code_eval_decode
{
    meta:
        description = "executes a freshly decoded string (eval or Function of Buffer.from, atob, unescape)"
    strings:
        $call = /(eval|new\s+Function|Function|runInThisContext|runInNewContext)\s*\(\s*(Buffer\.from|atob|unescape|decodeURIComponent|String\.fromCharCode)\s*\(/
        $b64 = /(eval|new\s+Function)\s*\(\s*["'`][A-Za-z0-9+\/=]{200,}/
        $hex = /eval\s*\(\s*["'](\\x[0-9a-fA-F]{2}){32,}/
    condition:
        any of them
}

rule hidden_code_python_exec_decode
{
    meta:
        description = "Python code that executes decoded or decompressed data"
    strings:
        $a = /exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|bz2\.decompress|lzma\.decompress|codecs\.decode)\s*\(/
        $b = /exec\s*\(\s*__import__\s*\(\s*["'](base64|zlib|marshal)["']\s*\)/
    condition:
        any of them
}

rule credential_store_harvest
{
    meta:
        description = "names several credential stores (npm, SSH, cloud, Git, browser or wallet files)"
    strings:
        $npmrc = ".npmrc"
        $ssh = /\.ssh["'\/\\]|id_(rsa|ed25519|ecdsa)\b/
        $aws = /\.aws["'\/\\]credentials/
        $gitcred = ".git-credentials"
        $gh = /gh["'\/\\]hosts\.yml/
        $docker = /\.docker["'\/\\]config\.json/
        $kube = /\.kube["'\/\\]config/
        $gcloud = "application_default_credentials.json"
        $browser = /Login Data|logins\.json|cookies\.sqlite/
        $wallet = /wallet\.dat|keystore["'\/\\]UTC--/
        $pypirc = ".pypirc"
    condition:
        3 of them
}

rule environment_harvest
{
    meta:
        description = "serialises the whole environment, where tokens and keys are kept"
    strings:
        $js = /JSON\.stringify\(\s*process\.env\s*[,)]/
        $py = /json\.dumps\(\s*dict\(\s*os\.environ\s*\)/
    condition:
        any of them
}

rule download_and_run
{
    meta:
        description = "downloads a program and runs it (curl/wget piped to a shell, PowerShell download, certutil)"
    strings:
        $pipe = /(curl|wget)[^\n;&|]{0,200}https?:\/\/[^\n;&|]{0,300}\|\s*(sudo\s+)?(ba|z|da)?sh\b/
        $ps_iex = /(iex|Invoke-Expression)\s*\(?\s*\(?\s*(New-Object\s+Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)/ nocase
        $ps_dl = /\.(DownloadString|DownloadFile)\s*\(\s*["']https?:\/\//
        $ps_enc = /powershell(\.exe)?[^\n]{0,80}\s-(e|ec|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{40,}/ nocase
        $certutil = /certutil(\.exe)?[^\n]{0,40}-urlcache[^\n]{0,40}-f/ nocase
    condition:
        any of them
}

rule exfiltration_endpoint
{
    meta:
        description = "contains an address commonly used to receive stolen data"
    strings:
        $discord = /discord(app)?\.com\/api\/webhooks\/[0-9]{5,}/
        $hooks = /https?:\/\/(webhook\.site|[a-z0-9-]+\.pipedream\.net|[a-z0-9-]+\.requestcatcher\.com|[a-z0-9-]+\.oast\.(pro|live|site|online|fun|me)|[a-z0-9-]+\.oastify\.com|[a-z0-9-]+\.burpcollaborator\.net|[a-z0-9-]+\.interact\.sh)/
        $tg = /api\.telegram\.org\/bot[0-9]{6,}:[A-Za-z0-9_-]{20,}/
    condition:
        any of them
}

rule startup_persistence
{
    meta:
        description = "registers code to run again later (shell startup file, cron, scheduled task, Run key)"
    strings:
        $append = /appendFile(Sync)?\s*\([^)\n]{0,200}\.(bashrc|zshrc|bash_profile|zprofile)/
        $cron = /\|\s*crontab\s+-\s*["')\n]/
        $schtasks = /schtasks(\.exe)?[^\n]{0,40}\/create/ nocase
        $runkey = /reg(\.exe)?\s+add\s+[^\n]{0,120}CurrentVersion\\{1,2}Run\b/ nocase
        $systemd = /systemctl\s+--user\s+enable/
    condition:
        any of them
}

rule ci_workflow_write
{
    meta:
        description = "writes GitHub Actions workflow files (CI backdoor)"
    strings:
        $w = /(writeFile|appendFile|mkdir)(Sync)?\s*\([^\n]{0,200}\.github["'\/\\, ]+workflows/
    condition:
        $w
}

rule javascript_obfuscator_output
{
    meta:
        description = "code processed by javascript-obfuscator (many _0x hex identifiers)"
    strings:
        $id = /_0x[a-f0-9]{4,6}\b/
    condition:
        #id >= 50
}

rule crypto_miner
{
    meta:
        description = "contains a cryptocurrency miner pool address or miner configuration"
    strings:
        $stratum = /stratum\+(tcp|ssl):\/\/[a-z0-9.-]+:[0-9]{2,5}/ nocase
        $xmrig = "\"donate-level\""
        $cfg = "--donate-level"
    condition:
        any of them
}

rule reverse_shell
{
    meta:
        description = "opens a reverse shell to a remote host"
    strings:
        $devtcp = /(ba)?sh\s+-i\s*[>&]+\s*\/dev\/tcp\/[0-9a-z.-]+\/[0-9]{2,5}/
        $nc = /\b(nc|ncat|netcat)\s+(-[a-z]+\s+)*-e\s+\/bin\/(ba)?sh\b/
        $py = /pty\.spawn\(\s*["']\/bin\/(ba)?sh["']\s*\)/
    condition:
        any of them
}
