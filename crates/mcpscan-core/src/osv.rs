//! OSV advisory lookups, behind `--online`. One allowlisted host, one batch
//! request, a 24h file cache.

use crate::model::{PackageRef, Registry};
use crate::netpolicy;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::Url;

/// One advisory hit for one package version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsvHit {
    /// Package name.
    pub package: String,
    /// Version that matched.
    pub version: String,
    /// Advisory IDs.
    pub ids: Vec<String>,
}

/// Lookup key used by the rule.
pub fn key(pkg: &PackageRef) -> String {
    let registry = match pkg.registry {
        Registry::Npm => "npm",
        Registry::PyPi => "pypi",
        Registry::Docker => "docker",
    };
    format!(
        "{registry}:{}@{}",
        pkg.name,
        pkg.version.as_deref().unwrap_or("")
    )
}

/// Why a lookup failed.
#[derive(Debug, thiserror::Error)]
pub enum OsvError {
    /// The configured base failed the outbound policy.
    #[error("{0}")]
    Policy(#[from] netpolicy::PolicyError),
    /// The base could not be parsed.
    #[error("invalid osv base: {0}")]
    Base(String),
    /// The request failed.
    #[error("request failed: {0}")]
    Request(String),
    /// The response was not the expected shape.
    #[error("unexpected response: {0}")]
    Response(String),
}

/// Advisory client.
pub struct OsvClient {
    base: Url,
    cache_dir: Option<PathBuf>,
    ttl: Duration,
}

impl OsvClient {
    /// Build a client for `base`, caching under `cache_dir`.
    pub fn new(base: Url, cache_dir: Option<PathBuf>) -> Self {
        Self {
            base,
            cache_dir,
            ttl: Duration::from_secs(24 * 60 * 60),
        }
    }

    /// Build from `MCPSCAN_OSV_BASE`, defaulting to `https://api.osv.dev`.
    pub fn from_env() -> Result<Self, OsvError> {
        let raw =
            std::env::var("MCPSCAN_OSV_BASE").unwrap_or_else(|_| "https://api.osv.dev".to_string());
        let base = Url::parse(&raw).map_err(|e| OsvError::Base(e.to_string()))?;
        let allow_loopback =
            cfg!(debug_assertions) && std::env::var("MCPSCAN_ALLOW_LOOPBACK").as_deref() == Ok("1");
        if !allow_loopback {
            netpolicy::check_host(&base, &["osv.dev"])?;
        }
        Ok(Self::new(base, cache_dir()))
    }

    /// Query every package that has a pinned version.
    pub fn query_batch(&self, packages: &[PackageRef]) -> Result<Vec<OsvHit>, OsvError> {
        let queries: Vec<serde_json::Value> = packages
            .iter()
            .filter(|p| p.version.is_some())
            .map(|p| {
                let ecosystem = match p.registry {
                    Registry::Npm => "npm",
                    Registry::PyPi => "PyPI",
                    Registry::Docker => "Docker",
                };
                serde_json::json!({
                    "package": { "ecosystem": ecosystem, "name": p.name },
                    "version": p.version,
                })
            })
            .collect();
        if queries.is_empty() {
            return Ok(Vec::new());
        }
        let body = serde_json::json!({ "queries": queries }).to_string();
        let text = self.post("/v1/querybatch", &body)?;
        parse_batch(&text, packages)
    }

    fn post(&self, path: &str, body: &str) -> Result<String, OsvError> {
        let url = self
            .base
            .join(path)
            .map_err(|e| OsvError::Base(e.to_string()))?;
        let key = cache_key(&url, body);
        if let Some(fresh) = self.read_cache(&key, true) {
            return Ok(fresh);
        }
        match ureq::post(url.as_str())
            .header("content-type", "application/json")
            .send(body)
        {
            Ok(mut response) => {
                let text = response
                    .body_mut()
                    .read_to_string()
                    .map_err(|e| OsvError::Request(e.to_string()))?;
                self.write_cache(&key, &text);
                Ok(text)
            }
            // Expired cache is never presented as a completed check: the scan
            // reports "could not check advisories" instead.
            Err(err) => Err(OsvError::Request(err.to_string())),
        }
    }

    fn cache_path(&self, key: &str) -> Option<PathBuf> {
        self.cache_dir
            .as_ref()
            .map(|dir| dir.join(format!("{key}.json")))
    }

    fn read_cache(&self, key: &str, require_fresh: bool) -> Option<String> {
        let path = self.cache_path(key)?;
        let text = std::fs::read_to_string(path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&text).ok()?;
        let now = now_secs();
        if require_fresh && now.saturating_sub(entry.fetched_at) > self.ttl.as_secs() {
            return None;
        }
        Some(entry.body)
    }

    fn write_cache(&self, key: &str, body: &str) {
        let Some(path) = self.cache_path(key) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let entry = CacheEntry {
            fetched_at: now_secs(),
            body: body.to_string(),
        };
        if let Ok(text) = serde_json::to_string(&entry) {
            let _ = std::fs::write(path, text);
        }
    }
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    fetched_at: u64,
    body: String,
}

fn cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("MCPSCAN_CACHE_DIR") {
        return Some(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".cache/mcpscan"))
}

fn cache_key(url: &Url, body: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_str().as_bytes());
    hasher.update(body.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_batch(text: &str, packages: &[PackageRef]) -> Result<Vec<OsvHit>, OsvError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| OsvError::Response(e.to_string()))?;
    let results = value["results"]
        .as_array()
        .ok_or_else(|| OsvError::Response("missing results".to_string()))?;
    let mut out = Vec::new();
    let pinned: Vec<&PackageRef> = packages.iter().filter(|p| p.version.is_some()).collect();
    for (index, result) in results.iter().enumerate() {
        let Some(pkg) = pinned.get(index) else {
            continue;
        };
        let ids: Vec<String> = result["vulns"]
            .as_array()
            .map(|vulns| {
                vulns
                    .iter()
                    .filter_map(|v| v["id"].as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        if !ids.is_empty() {
            out.push(OsvHit {
                package: pkg.name.clone(),
                version: pkg.version.clone().unwrap_or_default(),
                ids,
            });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, version: &str) -> PackageRef {
        PackageRef {
            registry: Registry::Npm,
            name: name.into(),
            version: Some(version.into()),
        }
    }

    #[test]
    fn batch_response_maps_to_hits() {
        let body = r#"{"results":[{"vulns":[{"id":"GHSA-1"}]},{"vulns":[]}]}"#;
        let hits = parse_batch(body, &[pkg("a", "1.0.0"), pkg("b", "2.0.0")]).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].ids, vec!["GHSA-1"]);
        assert_eq!(hits[0].version, "1.0.0");
    }

    #[test]
    fn key_includes_registry_name_and_version() {
        assert_eq!(key(&pkg("@scope/x", "1.2.3")), "npm:@scope/x@1.2.3");
    }
}
