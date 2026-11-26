use assert_cmd::Command;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

struct Fake {
    base: String,
    hits: Arc<AtomicUsize>,
}

fn fake_http(body: &'static str) -> Fake {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&hits);
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    counter.fetch_add(1, Ordering::SeqCst);
                    // Read the whole request (headers + body) before answering.
                    // Closing while the client is still writing resets the
                    // connection on Windows.
                    read_request(&mut stream);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes());
                    let _ = stream.flush();
                }
                Err(_) => std::thread::sleep(Duration::from_millis(10)),
            }
        }
    });
    Fake {
        base: format!("http://{addr}"),
        hits,
    }
}

fn read_request(stream: &mut std::net::TcpStream) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    let header_end;
    loop {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    header_end = pos + 4;
                    break;
                }
            }
        }
    }
    let headers = String::from_utf8_lossy(&buf[..header_end]).to_ascii_lowercase();
    let length: usize = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or(0);
    let mut remaining = length.saturating_sub(buf.len() - header_end);
    while remaining > 0 {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return,
            Ok(n) => remaining = remaining.saturating_sub(n),
        }
    }
}

fn config_with(server_json: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(".mcp.json"),
        format!(r#"{{"mcpServers":{{"s":{server_json}}}}}"#),
    )
    .unwrap();
    dir
}

fn scan(dir: &tempfile::TempDir, base: &str, online: bool) -> Command {
    let mut cmd = Command::cargo_bin("mcpscan").unwrap();
    cmd.current_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/../.."));
    cmd.env("MCPSCAN_OSV_BASE", base)
        .env("MCPSCAN_ALLOW_LOOPBACK", "1")
        .env("MCPSCAN_CACHE_DIR", dir.path().join("cache"));
    cmd.arg("scan").arg(dir.path());
    if online {
        cmd.arg("--online");
    }
    cmd
}

#[test]
fn vulnerable_pinned_version_produces_a_finding() {
    let fake = fake_http(r#"{"results":[{"vulns":[{"id":"GHSA-test-1234"}]}]}"#);
    let dir = config_with(
        r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@0.1.0"]}"#,
    );
    let mut cmd = scan(&dir, &fake.base, true);
    cmd.arg("--fail-on").arg("high");
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(2),
        "stdout={stdout} stderr={stderr}"
    );
    assert!(stdout.contains("mcp-osv-vulnerable"), "{stdout}");
    assert!(fake.hits.load(Ordering::SeqCst) > 0);
}

#[test]
fn offline_never_contacts_the_advisory_host() {
    let fake = fake_http(r#"{"results":[{"vulns":[]}]}"#);
    let dir = config_with(
        r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@0.1.0"]}"#,
    );
    scan(&dir, &fake.base, false).assert().code(0);
    std::thread::sleep(Duration::from_millis(150));
    assert_eq!(
        fake.hits.load(Ordering::SeqCst),
        0,
        "offline scan made a request"
    );
}

#[test]
fn a_scanned_url_is_never_fetched() {
    let target = fake_http(r#"{"ok":true}"#);
    let osv = fake_http(r#"{"results":[{"vulns":[]}]}"#);
    let dir = config_with(&format!(
        r#"{{"url":"{}/mcp","args":["-y","some-server@1.0.0"]}}"#,
        target.base
    ));
    scan(&dir, &osv.base, true).assert().code(0);
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        target.hits.load(Ordering::SeqCst),
        0,
        "the scan fetched a scanned server url"
    );
}

#[test]
fn advisory_failure_is_exit_three() {
    let dir = config_with(
        r#"{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@0.1.0"]}"#,
    );
    scan(&dir, "http://127.0.0.1:1", true)
        .assert()
        .code(3)
        .stderr(predicates::str::contains("could not check advisories"));
}
