//! Finding the config files a scan should read. Pure: no filesystem access.

use std::path::{Path, PathBuf};

/// Platform whose user-scope paths apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Linux and other XDG systems.
    Linux,
    /// macOS.
    MacOs,
    /// Windows.
    Windows,
}

impl Platform {
    /// The platform this binary was built for.
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "windows") {
            Platform::Windows
        } else {
            Platform::Linux
        }
    }
}

/// What to look for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoverOptions {
    /// Directory the project-scope paths are relative to.
    pub root: PathBuf,
    /// Also return per-user config paths.
    pub include_user: bool,
    /// Also return shell history files.
    pub include_history: bool,
}

impl Default for DiscoverOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            include_user: false,
            include_history: false,
        }
    }
}

const PROJECT_PATHS: [&str; 9] = [
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".windsurf/mcp_config.json",
    ".zed/settings.json",
    ".claude/settings.json",
    ".env",
];

/// All candidate paths for one scan, in a stable order.
pub fn candidates(opts: &DiscoverOptions) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = PROJECT_PATHS.iter().map(|p| opts.root.join(p)).collect();
    out.push(opts.root.join(".env.local"));
    if opts.include_user {
        out.extend(user_candidates(Platform::current()));
    }
    if opts.include_history {
        out.extend(history_candidates());
    }
    dedupe_sorted(out)
}

/// Per-user config paths for a platform.
pub fn user_candidates(platform: Platform) -> Vec<PathBuf> {
    let home = home_dir();
    let mut out = Vec::new();
    match platform {
        Platform::Linux => {
            out.push(home.join(".claude.json"));
            out.push(home.join(".cursor/mcp.json"));
            out.push(home.join(".config/Claude/claude_desktop_config.json"));
            out.push(home.join(".config/Codeium/windsurf/mcp_config.json"));
        }
        Platform::MacOs => {
            out.push(home.join(".claude.json"));
            out.push(home.join(".cursor/mcp.json"));
            out.push(home.join("Library/Application Support/Claude/claude_desktop_config.json"));
            out.push(home.join("Library/Application Support/Codeium/windsurf/mcp_config.json"));
        }
        Platform::Windows => {
            out.push(home.join(".claude.json"));
            out.push(home.join(".cursor/mcp.json"));
            out.push(home.join("AppData/Roaming/Claude/claude_desktop_config.json"));
            out.push(home.join("AppData/Roaming/Codeium/windsurf/mcp_config.json"));
        }
    }
    out.push(home.join(".codex/config.toml"));
    dedupe_sorted(out)
}

fn history_candidates() -> Vec<PathBuf> {
    let home = home_dir();
    vec![
        home.join(".zsh_history"),
        home.join(".bash_history"),
        home.join(".config/fish/fish_history"),
    ]
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Sort and drop duplicates, keeping the first occurrence.
pub fn dedupe_sorted(mut paths: Vec<PathBuf>) -> Vec<PathBuf> {
    paths.sort();
    paths.dedup();
    paths
}

/// True when the path looks like a shell history file.
pub fn is_history(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some(".zsh_history" | ".bash_history" | "fish_history")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_scope_finds_the_project_files() {
        let found = candidates(&DiscoverOptions::default());
        let names: Vec<_> = found
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        for expected in [".mcp.json", "mcp.json", "mcp_config.json"] {
            assert!(names.contains(&expected.to_string()), "missing {expected}");
        }
        assert!(found.contains(&PathBuf::from("./.cursor/mcp.json")));
        assert!(found.contains(&PathBuf::from("./.vscode/mcp.json")));
    }

    #[test]
    fn user_scope_is_platform_specific() {
        let linux = user_candidates(Platform::Linux);
        assert!(
            linux
                .iter()
                .any(|p| p.ends_with(".config/Claude/claude_desktop_config.json"))
        );
        assert!(linux.iter().any(|p| p.ends_with(".codex/config.toml")));
        let mac = user_candidates(Platform::MacOs);
        assert!(mac.iter().any(|p| p.to_string_lossy().contains("Application Support/Claude")));
        let win = user_candidates(Platform::Windows);
        assert!(win.iter().any(|p| p.to_string_lossy().contains("AppData")));
    }

    #[test]
    fn history_is_opt_in() {
        let off = candidates(&DiscoverOptions::default());
        let on = candidates(&DiscoverOptions {
            include_history: true,
            ..Default::default()
        });
        assert!(!off.iter().any(|p| p.ends_with(".zsh_history")));
        assert!(on.iter().any(|p| p.ends_with(".zsh_history")));
        assert!(on.iter().any(|p| is_history(p)));
    }

    #[test]
    fn user_paths_are_only_included_when_asked() {
        let off = candidates(&DiscoverOptions::default());
        assert!(!off.iter().any(|p| p.to_string_lossy().contains("claude_desktop_config")));
        let on = candidates(&DiscoverOptions {
            include_user: true,
            ..Default::default()
        });
        assert!(on.iter().any(|p| p.to_string_lossy().contains("claude_desktop_config")));
    }

    #[test]
    fn output_is_sorted_and_unique() {
        let found = candidates(&DiscoverOptions {
            include_user: true,
            include_history: true,
            ..Default::default()
        });
        let mut sorted = found.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(found, sorted);
    }
}
