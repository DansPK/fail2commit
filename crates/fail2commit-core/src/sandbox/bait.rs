//! FR-024 bait credentials (coordinator-owned, frozen API).
//!
//! A fresh [`BaitSet`] per sandbox job: realistic fake credentials written
//! into the job's own home directory and token environment variables. Values
//! are random per job, so a value seen anywhere else came from this job.
//! Backends watch the files (Linux inotify / fanotify, Windows oplocks) and
//! the egress path for the values; a touch is an `ActivityKind::Bait` entry
//! and stops the job. Bait never leaves the job's stage.

use std::path::{Path, PathBuf};

pub struct BaitFile {
    /// Relative to the job's home directory (`HOME` / `USERPROFILE`).
    pub rel: PathBuf,
    pub contents: String,
}

pub struct BaitSet {
    pub files: Vec<BaitFile>,
    /// Variables to add to the job environment.
    pub env: Vec<(String, String)>,
    values: Vec<String>,
}

const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn random(n: usize, set: &[u8]) -> crate::Result<String> {
    let mut raw = vec![0u8; n];
    getrandom::fill(&mut raw).map_err(|e| crate::Error::internal(format!("random: {e}")))?;
    Ok(raw
        .iter()
        .map(|b| set[*b as usize % set.len()] as char)
        .collect())
}

impl BaitSet {
    pub fn generate() -> crate::Result<BaitSet> {
        let npm = format!("npm_{}", random(36, ALNUM)?);
        let gh = format!("ghp_{}", random(36, ALNUM)?);
        let pypi = format!("pypi-AgEIcHlwaS5vcmc{}", random(48, ALNUM)?);
        let aws_id = format!("AKIA{}", random(16, UPPER)?);
        let aws_secret = random(40, ALNUM)?;
        let ssh = random(64, ALNUM)?;
        let git_pw = random(32, ALNUM)?;
        let files = vec![
            file(".npmrc", format!("//registry.npmjs.org/:_authToken={npm}\n")),
            file(".pypirc", format!("[pypi]\nusername = __token__\npassword = {pypi}\n")),
            file(".git-credentials", format!("https://ci-bot:{git_pw}@github.com\n")),
            file(".config/gh/hosts.yml", format!("github.com:\n    oauth_token: {gh}\n    user: ci-bot\n")),
            file(
                ".aws/credentials",
                format!("[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_secret}\n"),
            ),
            file(
                ".ssh/id_ed25519",
                format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{ssh}\n-----END OPENSSH PRIVATE KEY-----\n"),
            ),
            file(".env", format!("GITHUB_TOKEN={gh}\nAWS_SECRET_ACCESS_KEY={aws_secret}\n")),
        ];
        let env = vec![
            ("NPM_TOKEN".to_string(), npm.clone()),
            ("GITHUB_TOKEN".to_string(), gh.clone()),
            ("AWS_ACCESS_KEY_ID".to_string(), aws_id.clone()),
            ("AWS_SECRET_ACCESS_KEY".to_string(), aws_secret.clone()),
        ];
        let values = vec![npm, gh, pypi, aws_id, aws_secret, ssh, git_pw];
        Ok(BaitSet { files, env, values })
    }

    /// Write the bait files under `home`; returns their absolute paths.
    /// `home` must be inside the job's own writable stage.
    pub fn write_into(&self, home: &Path) -> crate::Result<Vec<PathBuf>> {
        let mut out = Vec::with_capacity(self.files.len());
        for f in &self.files {
            let path = home.join(&f.rel);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(&path, &f.contents)?;
            out.push(path);
        }
        Ok(out)
    }

    /// The first bait value contained in `haystack`, compared ASCII
    /// case-insensitively (DNS names lose case).
    pub fn find_value(&self, haystack: &[u8]) -> Option<&str> {
        let hay = haystack.to_ascii_lowercase();
        self.values.iter().map(String::as_str).find(|v| {
            let needle = v.to_ascii_lowercase();
            hay.windows(needle.len()).any(|w| w == needle.as_bytes())
        })
    }
}

fn file(rel: &str, contents: String) -> BaitFile {
    BaitFile {
        rel: PathBuf::from(rel),
        contents,
    }
}

#[cfg(test)]
mod tests {
    use super::BaitSet;

    #[test]
    fn values_are_unique_per_job_and_found_case_insensitively() {
        let a = BaitSet::generate().unwrap();
        let b = BaitSet::generate().unwrap();
        let gh = &a.env.iter().find(|(k, _)| k == "GITHUB_TOKEN").unwrap().1;
        assert_ne!(
            gh,
            &b.env.iter().find(|(k, _)| k == "GITHUB_TOKEN").unwrap().1
        );
        let host = format!("{}.attacker.example", gh.to_ascii_lowercase());
        assert_eq!(a.find_value(host.as_bytes()), Some(gh.as_str()));
        assert_eq!(b.find_value(host.as_bytes()), None);
        assert_eq!(a.find_value(b"GET / HTTP/1.1"), None);
    }

    #[test]
    fn files_land_under_the_given_home_only() {
        let dir = tempfile::tempdir().unwrap();
        let set = BaitSet::generate().unwrap();
        let paths = set.write_into(dir.path()).unwrap();
        assert_eq!(paths.len(), set.files.len());
        assert!(paths
            .iter()
            .all(|p| p.starts_with(dir.path()) && p.is_file()));
    }
}
