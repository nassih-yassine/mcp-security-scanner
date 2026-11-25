//! Outbound URL policy. One allowlist, https only, public hosts only. Nothing
//! here ever sees a scanned server's `url`.

use url::Url;

/// Why a URL was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    /// Scheme is not https.
    #[error("refusing non-https url: {0}")]
    Scheme(String),
    /// URL carries credentials.
    #[error("refusing url with userinfo: {0}")]
    Userinfo(String),
    /// Port is not the scheme default.
    #[error("refusing non-default port: {0}")]
    Port(String),
    /// Host is not on the allowlist.
    #[error("refusing unlisted host: {0}")]
    Host(String),
    /// Host is an IP literal that is not public.
    #[error("refusing non-public address: {0}")]
    Address(String),
}

/// Accept `url` only if its host is `allowed` or a subdomain of it.
pub fn check_host(url: &Url, allowed: &[&str]) -> Result<(), PolicyError> {
    let raw = url.as_str().to_string();
    if url.scheme() != "https" {
        return Err(PolicyError::Scheme(raw));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(PolicyError::Userinfo(raw));
    }
    if let Some(port) = url.port() {
        if port != 443 {
            return Err(PolicyError::Port(raw));
        }
    }
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() {
        return Err(PolicyError::Host(raw));
    }
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(PolicyError::Address(raw));
    }
    let listed = allowed.iter().any(|entry| {
        let entry = entry.to_ascii_lowercase();
        host == entry || host.ends_with(&format!(".{entry}"))
    });
    if !listed {
        return Err(PolicyError::Host(raw));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(raw: &str) -> Result<(), PolicyError> {
        check_host(&url::Url::parse(raw).unwrap(), &["osv.dev"])
    }

    #[test]
    fn rejects_non_https_userinfo_and_unknown_hosts() {
        for bad in [
            "http://osv.dev/v1/query",
            "https://user:pw@osv.dev/x",
            "https://evil.test/x",
            "https://osv.dev.evil.test/x",
            "https://10.0.0.5/x",
            "https://169.254.169.254/latest/meta-data",
            "https://127.0.0.1/x",
            "https://[::1]/x",
        ] {
            assert!(check(bad).is_err(), "{bad} was allowed");
        }
    }

    #[test]
    fn allows_the_osv_host_and_subdomains() {
        assert!(check("https://api.osv.dev/v1/query").is_ok());
        assert!(check("https://osv.dev/v1/query").is_ok());
        assert!(check("https://api.osv.dev:443/v1/query").is_ok());
    }

    #[test]
    fn rejects_custom_ports() {
        assert!(check("https://api.osv.dev:8443/v1/query").is_err());
    }
}
