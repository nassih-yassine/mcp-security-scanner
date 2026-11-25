//! Reading every editor's MCP config shape into [`ServerSpec`].

use crate::model::{Capabilities, ConfigFormat, ServerSpec, Source, Span, Transport};
use jsonc_parser::ast::Value;
use jsonc_parser::{CollectOptions, ParseOptions};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

/// Refuse to read configs larger than this. A config is a few kilobytes; a
/// larger file is either not a config or an attempt to exhaust memory.
pub const MAX_CONFIG_BYTES: u64 = 5 * 1024 * 1024;

const CONTAINER_KEYS: [&str; 3] = ["mcpServers", "servers", "context_servers"];

/// Why a config could not be read.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    /// File exceeds [`MAX_CONFIG_BYTES`].
    #[error("{path}: larger than {limit} bytes")]
    TooLarge {
        /// Offending file.
        path: PathBuf,
        /// Configured limit.
        limit: u64,
    },
    /// File is not valid UTF-8.
    #[error("{path}: not valid UTF-8")]
    NotUtf8 {
        /// Offending file.
        path: PathBuf,
    },
    /// File is not parseable as its format.
    #[error("{path}: {message}")]
    Syntax {
        /// Offending file.
        path: PathBuf,
        /// Parser message.
        message: String,
    },
    /// The file could not be read from disk.
    #[error("{path}: {source}")]
    Io {
        /// Offending file.
        path: PathBuf,
        /// Underlying error.
        #[source]
        source: std::io::Error,
    },
}

/// An entry that was present but whose shape could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unreadable {
    /// File it was in.
    pub file: PathBuf,
    /// JSON pointer to the entry.
    pub pointer: String,
    /// What was wrong with it.
    pub reason: String,
}

/// Everything one config file contributed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ParsedConfig {
    /// Servers found, sorted by name.
    pub servers: Vec<ServerSpec>,
    /// Entries that could not be read.
    pub unreadable: Vec<Unreadable>,
}

/// Pick a format from the file extension.
pub fn format_for(path: &Path) -> ConfigFormat {
    match path.extension().and_then(|e| e.to_str()) {
        Some("toml") => ConfigFormat::Toml,
        Some("jsonc") => ConfigFormat::Jsonc,
        _ => ConfigFormat::Json,
    }
}

/// Read and parse one config file.
pub fn parse_file(path: &Path) -> Result<ParsedConfig, ParseError> {
    let meta = std::fs::metadata(path).map_err(|source| ParseError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if meta.len() > MAX_CONFIG_BYTES {
        return Err(ParseError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    let bytes = std::fs::read(path).map_err(|source| ParseError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse_bytes(&bytes, path, format_for(path))
}

/// Parse bytes that were already read.
pub fn parse_bytes(
    bytes: &[u8],
    path: &Path,
    format: ConfigFormat,
) -> Result<ParsedConfig, ParseError> {
    if bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ParseError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    let src = std::str::from_utf8(bytes).map_err(|_| ParseError::NotUtf8 {
        path: path.to_path_buf(),
    })?;
    parse_str(src, path, format)
}

/// Parse config text.
pub fn parse_str(src: &str, path: &Path, format: ConfigFormat) -> Result<ParsedConfig, ParseError> {
    if src.len() as u64 > MAX_CONFIG_BYTES {
        return Err(ParseError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_CONFIG_BYTES,
        });
    }
    let src = src.strip_prefix('\u{feff}').unwrap_or(src);
    let mut parsed = match format {
        ConfigFormat::Toml => parse_toml(src, path)?,
        _ => parse_jsonc(src, path, format)?,
    };
    parsed.servers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(parsed)
}

fn parse_jsonc(src: &str, path: &Path, format: ConfigFormat) -> Result<ParsedConfig, ParseError> {
    let ast = jsonc_parser::parse_to_ast(
        src,
        &CollectOptions {
            comments: jsonc_parser::CommentCollectionStrategy::Off,
            tokens: false,
        },
        &ParseOptions::default(),
    )
    .map_err(|e| ParseError::Syntax {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let Some(Value::Object(root)) = ast.value else {
        return Ok(ParsedConfig::default());
    };
    let mut out = ParsedConfig::default();
    for key in CONTAINER_KEYS {
        let Some(prop) = root.properties.iter().find(|p| p.name.as_str() == key) else {
            continue;
        };
        match &prop.value {
            Value::Object(obj) => {
                for entry in &obj.properties {
                    let pointer = format!("/{key}/{}", entry.name.as_str());
                    let span = Some(span_of(src, range_of(&entry.value)));
                    read_entry(
                        src,
                        path,
                        format,
                        entry.name.as_str(),
                        &pointer,
                        &entry.value,
                        span,
                        &mut out,
                    );
                }
            }
            other => {
                out.unreadable.push(Unreadable {
                    file: path.to_path_buf(),
                    pointer: format!("/{key}"),
                    reason: format!("expected an object, found {}", kind_of(other)),
                });
            }
        }
        break;
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn read_entry(
    src: &str,
    path: &Path,
    format: ConfigFormat,
    name: &str,
    pointer: &str,
    value: &Value,
    span: Option<Span>,
    out: &mut ParsedConfig,
) {
    let Value::Object(obj) = value else {
        out.unreadable.push(Unreadable {
            file: path.to_path_buf(),
            pointer: pointer.to_string(),
            reason: format!("expected an object, found {}", kind_of(value)),
        });
        out.servers.push(ServerSpec {
            id: server_id(path, pointer),
            name: name.to_string(),
            source: Source {
                file: path.to_path_buf(),
                format,
                pointer: pointer.to_string(),
                span,
            },
            transport: Transport::Stdio,
            command: None,
            args: Vec::new(),
            env: BTreeMap::new(),
            url: None,
            headers: BTreeMap::new(),
            pkg: None,
            tools: Vec::new(),
            declared_scopes: Vec::new(),
            capabilities: Capabilities::default(),
        });
        return;
    };

    let field = |key: &str| obj.properties.iter().find(|p| p.name.as_str() == key);
    let command = field("command").and_then(|p| command_of(&p.value));
    let url = field("url").and_then(|p| string_of(&p.value));
    let args = field("args").map(|p| args_of(&p.value)).unwrap_or_default();
    let env = field("env").map(|p| map_of(&p.value)).unwrap_or_default();
    let headers = field("headers")
        .map(|p| map_of(&p.value))
        .unwrap_or_default();
    let declared_scopes = field("scopes")
        .map(|p| args_of(&p.value))
        .unwrap_or_default();
    let transport = match field("type").and_then(|p| string_of(&p.value)).as_deref() {
        Some("sse") => Transport::Sse,
        Some("http") | Some("streamable-http") => Transport::Http,
        _ if url.is_some() => Transport::Http,
        _ => Transport::Stdio,
    };

    out.servers.push(ServerSpec {
        id: server_id(path, pointer),
        name: name.to_string(),
        source: Source {
            file: path.to_path_buf(),
            format,
            pointer: pointer.to_string(),
            span,
        },
        transport,
        command,
        args,
        env,
        url,
        headers,
        pkg: None,
        tools: Vec::new(),
        declared_scopes,
        capabilities: Capabilities::default(),
    });
    let _ = src;
}

fn parse_toml(src: &str, path: &Path) -> Result<ParsedConfig, ParseError> {
    let doc = toml_edit::Document::parse(src).map_err(|e| ParseError::Syntax {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;
    let mut out = ParsedConfig::default();
    let Some(container) = doc
        .as_table()
        .get("mcp_servers")
        .and_then(|i| i.as_table_like())
    else {
        return Ok(out);
    };
    for (name, item) in container.iter() {
        let pointer = format!("/mcp_servers/{name}");
        let span = item.span().map(|r| span_of(src, r));
        let Some(table) = item.as_table_like() else {
            out.unreadable.push(Unreadable {
                file: path.to_path_buf(),
                pointer,
                reason: "expected a table".to_string(),
            });
            continue;
        };
        let get = |key: &str| table.get(key);
        let command = get("command").and_then(|i| i.as_str()).map(str::to_string);
        let url = get("url").and_then(|i| i.as_str()).map(str::to_string);
        let args = get("args")
            .and_then(|i| i.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        let transport = if url.is_some() {
            Transport::Http
        } else {
            Transport::Stdio
        };
        out.servers.push(ServerSpec {
            id: server_id(path, &pointer),
            name: name.to_string(),
            source: Source {
                file: path.to_path_buf(),
                format: ConfigFormat::Toml,
                pointer,
                span,
            },
            transport,
            command,
            args,
            env: BTreeMap::new(),
            url,
            headers: BTreeMap::new(),
            pkg: None,
            tools: Vec::new(),
            declared_scopes: Vec::new(),
            capabilities: Capabilities::default(),
        });
    }
    Ok(out)
}

fn server_id(path: &Path, pointer: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(path.to_string_lossy().as_bytes());
    hasher.update([0]);
    hasher.update(pointer.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in hasher.finalize() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn range_of(value: &Value) -> std::ops::Range<usize> {
    match value {
        Value::StringLit(v) => v.range.start..v.range.end,
        Value::NumberLit(v) => v.range.start..v.range.end,
        Value::BooleanLit(v) => v.range.start..v.range.end,
        Value::Object(v) => v.range.start..v.range.end,
        Value::Array(v) => v.range.start..v.range.end,
        Value::NullKeyword(v) => v.range.start..v.range.end,
    }
}

fn span_of(src: &str, range: std::ops::Range<usize>) -> Span {
    let (start_line, start_col) = line_col(src, range.start);
    let (end_line, end_col) = line_col(src, range.end);
    Span {
        start_line,
        start_col,
        end_line,
        end_col,
    }
}

fn line_col(src: &str, byte: usize) -> (usize, usize) {
    let byte = byte.min(src.len());
    let before = &src[..byte];
    let line = before.bytes().filter(|b| *b == b'\n').count() + 1;
    let col = before.rfind('\n').map(|i| byte - i).unwrap_or(byte + 1);
    (line, col)
}

fn kind_of(value: &Value) -> &'static str {
    match value {
        Value::StringLit(_) => "a string",
        Value::NumberLit(_) => "a number",
        Value::BooleanLit(_) => "a boolean",
        Value::Object(_) => "an object",
        Value::Array(_) => "an array",
        Value::NullKeyword(_) => "null",
    }
}

fn string_of(value: &Value) -> Option<String> {
    match value {
        Value::StringLit(v) => Some(v.value.to_string()),
        Value::NumberLit(v) => Some(v.value.to_string()),
        Value::BooleanLit(v) => Some(v.value.to_string()),
        _ => None,
    }
}

fn command_of(value: &Value) -> Option<String> {
    if let Some(s) = string_of(value) {
        return Some(s);
    }
    if let Value::Object(obj) = value {
        return obj
            .properties
            .iter()
            .find(|p| p.name.as_str() == "path")
            .and_then(|p| string_of(&p.value));
    }
    None
}

fn args_of(value: &Value) -> Vec<String> {
    match value {
        Value::Array(arr) => arr.elements.iter().filter_map(string_of).collect(),
        other => string_of(other).map(|s| vec![s]).unwrap_or_default(),
    }
}

fn map_of(value: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    if let Value::Object(obj) = value {
        for prop in &obj.properties {
            if let Some(v) = string_of(&prop.value) {
                out.insert(prop.name.as_str().to_string(), v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures")
            .join(rel)
    }

    #[test]
    fn reads_all_five_shapes() {
        for (path, expected) in [
            ("_parse/claude.json", "claude-desktop"),
            ("_parse/cursor.jsonc", "cursor-server"),
            ("_parse/vscode.json", "vscode-server"),
            ("_parse/zed.json", "zed-server"),
            ("_parse/codex.toml", "codex-server"),
        ] {
            let parsed = parse_file(&fixture(path)).unwrap();
            assert_eq!(parsed.servers.len(), 1, "{path}");
            assert_eq!(parsed.servers[0].name, expected, "{path}");
            assert!(parsed.servers[0].source.span.is_some(), "{path} lost spans");
        }
    }

    #[test]
    fn jsonc_comments_and_bom_do_not_shift_spans() {
        let src = "\u{feff}{\n  // comment\n  \"mcpServers\": { \"s\": { \"command\": \"x\" } }\n}";
        let parsed = parse_str(src, Path::new("c.jsonc"), ConfigFormat::Jsonc).unwrap();
        let span = parsed.servers[0].source.span.unwrap();
        assert_eq!(span.start_line, 3);
    }

    #[test]
    fn double_slash_inside_a_string_is_not_a_comment() {
        let src = r#"{"mcpServers":{"s":{"url":"https://example.test/a"}}}"#;
        let parsed = parse_str(src, Path::new("c.json"), ConfigFormat::Json).unwrap();
        assert_eq!(
            parsed.servers[0].url.as_deref(),
            Some("https://example.test/a")
        );
    }

    #[test]
    fn wrong_shaped_entry_is_unreadable_but_counted() {
        for src in [
            r#"{"mcpServers":"nope"}"#,
            r#"{"mcpServers":null}"#,
            r#"{"mcpServers":[]}"#,
        ] {
            let parsed = parse_str(src, Path::new("c.json"), ConfigFormat::Json).unwrap();
            assert_eq!(parsed.servers.len(), 0);
            assert_eq!(parsed.unreadable.len(), 1, "{src}");
        }
        let mixed = r#"{"mcpServers":{"ok":{"command":"x"},"bad":"str"}}"#;
        let parsed = parse_str(mixed, Path::new("c.json"), ConfigFormat::Json).unwrap();
        assert_eq!(parsed.servers.len(), 2);
        assert_eq!(parsed.unreadable.len(), 1);
        assert!(parsed.servers.iter().any(|s| s.name == "bad"));
    }

    #[test]
    fn oversized_and_invalid_utf8_are_errors() {
        let big = "x".repeat(MAX_CONFIG_BYTES as usize + 1);
        assert!(matches!(
            parse_str(&big, Path::new("big.json"), ConfigFormat::Json),
            Err(ParseError::TooLarge { .. })
        ));
        let bad = std::fs::read(fixture("_parse/invalid-utf8.json")).unwrap();
        let err = parse_bytes(&bad, Path::new("bad.json"), ConfigFormat::Json).unwrap_err();
        assert!(matches!(err, ParseError::NotUtf8 { .. }));
    }

    #[test]
    fn crlf_does_not_break_lines() {
        let src = "{\r\n  \"mcpServers\": {\r\n    \"s\": {\"command\":\"x\"}\r\n  }\r\n}";
        let parsed = parse_str(src, Path::new("c.json"), ConfigFormat::Json).unwrap();
        assert_eq!(parsed.servers[0].source.span.unwrap().start_line, 3);
    }

    #[test]
    fn env_and_headers_are_read_as_strings() {
        let src =
            r#"{"mcpServers":{"s":{"command":"x","env":{"A":1,"B":true},"headers":{"H":"v"}}}}"#;
        let parsed = parse_str(src, Path::new("c.json"), ConfigFormat::Json).unwrap();
        let s = &parsed.servers[0];
        assert_eq!(s.env.get("A").map(String::as_str), Some("1"));
        assert_eq!(s.env.get("B").map(String::as_str), Some("true"));
        assert_eq!(s.headers.get("H").map(String::as_str), Some("v"));
    }

    #[test]
    fn pointer_and_format_are_recorded() {
        let parsed = parse_str(
            r#"{"mcpServers":{"s":{"command":"x"}}}"#,
            Path::new("sub/.mcp.json"),
            ConfigFormat::Json,
        )
        .unwrap();
        assert_eq!(parsed.servers[0].source.pointer, "/mcpServers/s");
        assert_eq!(parsed.servers[0].source.format, ConfigFormat::Json);
        assert_eq!(
            parsed.servers[0].source.file.to_string_lossy(),
            "sub/.mcp.json"
        );
    }
}
