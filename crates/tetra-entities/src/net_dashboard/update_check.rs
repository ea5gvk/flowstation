//! Git-based update-check for the dashboard.
//!
//! Compares the running build (the commit hash baked into the binary) against the tip of the
//! remote branch the source tree is checked out on — the same `origin/<branch>` the OTA path
//! (`run_update`) fast-forwards to. A fork branch (e.g. `miura`) is therefore told about its own
//! new commits, not about upstream releases the OTA would never bring in. This is purely
//! informational: we only surface an "update available" badge so the operator knows to click it.
//!
//! The check is best-effort: any git/network failure yields `UpdateCheck::unknown()`
//! rather than an error, so a flaky connection never breaks the dashboard.

use std::path::Path;
use std::process::{Command, Stdio};

/// Result of an update check, serialised to JSON for the dashboard.
#[derive(Debug, Clone)]
pub struct UpdateCheck {
    /// Locally built version string (as-is, e.g. "v0.2.5-2aad62c8").
    pub current: String,
    /// Remote branch tip, if the check succeeded (e.g. "miura b349882a (+3)").
    pub latest: Option<String>,
    /// True when the remote branch has commits the running binary was not built from.
    pub update_available: bool,
    /// URL of the latest release page, if available (for a "view release" link).
    pub release_url: Option<String>,
    /// True when the check itself failed (network/parse). The badge should stay hidden.
    pub check_failed: bool,
}

impl UpdateCheck {
    fn unknown(current: &str) -> Self {
        UpdateCheck {
            current: current.to_string(),
            latest: None,
            update_available: false,
            release_url: None,
            check_failed: true,
        }
    }

    /// Render as a JSON object for `GET /api/update/check`.
    pub fn to_json(&self) -> String {
        let latest = self
            .latest
            .as_deref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string());
        let url = self
            .release_url
            .as_deref()
            .map(|s| format!("\"{}\"", json_escape(s)))
            .unwrap_or_else(|| "null".to_string());
        format!(
            "{{\"current\":\"{}\",\"latest\":{},\"update_available\":{},\"release_url\":{},\"check_failed\":{}}}",
            json_escape(&self.current),
            latest,
            self.update_available,
            url,
            self.check_failed
        )
    }
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Fetch the remote branch `src_dir` is checked out on and count the commits on it that the
/// running binary (`binary_git_hash`, e.g. `tetra_core::GIT_HASH`) was not built from.
/// `src_dir` is None when no trusted source tree was found. Blocking (runs `git fetch`);
/// call from a worker thread.
pub fn check_for_update(current_version: &str, binary_git_hash: &str, src_dir: Option<&Path>) -> UpdateCheck {
    let Some(dir) = src_dir else {
        return UpdateCheck::unknown(current_version);
    };
    // Never prompt for credentials, and abort a stalled fetch instead of hanging the handler.
    let git = |args: &[&str]| -> Option<String> {
        let out = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=10"])
            .args(args)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .output()
            .ok()?;
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    };

    // Same branch selection as run_update: the checked-out branch, `main` on a detached HEAD.
    let branch = git(&["rev-parse", "--abbrev-ref", "HEAD"])
        .filter(|b| !b.is_empty() && b != "HEAD")
        .unwrap_or_else(|| "main".to_string());
    let remote_ref = format!("origin/{}", branch);
    if git(&["fetch", "--quiet", "origin", branch.as_str()]).is_none() {
        return UpdateCheck::unknown(current_version);
    }
    let Some(remote_short) = git(&["rev-parse", "--short=8", remote_ref.as_str()]) else {
        return UpdateCheck::unknown(current_version);
    };

    // Count from the commit the binary was built from; fall back to the tree's HEAD when the
    // build embedded no hash or that commit is not in this clone.
    let bin = binary_git_hash.strip_suffix("-modified").unwrap_or(binary_git_hash);
    let bin_commit = format!("{}^{{commit}}", bin);
    let base = if bin.is_empty() || bin == "unknown" || git(&["cat-file", "-e", bin_commit.as_str()]).is_none() {
        "HEAD"
    } else {
        bin
    };
    let range = format!("{}..{}", base, remote_ref);
    let Some(behind) = git(&["rev-list", "--count", range.as_str()]).and_then(|n| n.parse::<u32>().ok()) else {
        return UpdateCheck::unknown(current_version);
    };

    UpdateCheck {
        current: current_version.to_string(),
        latest: Some(format!("{} {} (+{})", branch, remote_short, behind)),
        update_available: behind > 0,
        release_url: None,
        check_failed: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_source_tree_is_unknown() {
        let uc = check_for_update("v0.2.5-2aad62c8", "2aad62c8", None);
        assert!(uc.check_failed);
        assert!(!uc.update_available);
    }

    #[test]
    fn json_output() {
        let uc = UpdateCheck {
            current: "v0.2.5-gabc".to_string(),
            latest: Some("v0.2.6".to_string()),
            update_available: true,
            release_url: Some("https://github.com/razvanzeces/flowstation/releases/tag/v0.2.6".to_string()),
            check_failed: false,
        };
        let j = uc.to_json();
        assert!(j.contains("\"update_available\":true"));
        assert!(j.contains("\"latest\":\"v0.2.6\""));
        assert!(j.contains("\"check_failed\":false"));
    }
}
