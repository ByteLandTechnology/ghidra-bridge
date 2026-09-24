use std::collections::hash_map::RandomState;
use std::fs::{self, File};
use std::hash::{BuildHasher, Hasher};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context, Result};

use crate::mcp::McpClient;

pub const PROJECT_NAME: &str = "mcp_client";
pub const SESSION_ID: &str = "mcp-client";
pub const MCP_PATH: &str = "/mcp";

/// A headless Ghidra process that serves the bridge over MCP.
///
/// Dropping the value kills the process if it is still running.
pub struct GhidraProcess {
    child: Option<Child>,
    log_path: PathBuf,
    port: u16,
    token: String,
}

impl GhidraProcess {
    pub fn start(
        ghidra_install_dir: &Path,
        script_dir: &Path,
        binary: &Path,
        work_dir: &Path,
    ) -> Result<Self> {
        let analyze_headless = analyze_headless_path(ghidra_install_dir)?;
        let script_dir = canonical(script_dir, "script directory")?;
        for required in ["GhidraMcp.java", "ghidra-bridge.jar"] {
            ensure!(
                script_dir.join(required).is_file(),
                "{} does not contain {required}; run ./gradlew buildGhidraScript first",
                script_dir.display()
            );
        }
        let binary = canonical(binary, "binary")?;
        ensure!(binary.is_file(), "{} is not a file", binary.display());

        let project_dir = work_dir.join("project");
        fs::create_dir_all(&project_dir)
            .with_context(|| format!("cannot create {}", project_dir.display()))?;
        let log_path = work_dir.join("ghidra.log");
        let log = File::create(&log_path)
            .with_context(|| format!("cannot create {}", log_path.display()))?;

        let port = free_port()?;
        let token = random_token();
        let child = Command::new(&analyze_headless)
            .arg(&project_dir)
            .arg(PROJECT_NAME)
            .arg("-import")
            .arg(&binary)
            .arg("-scriptPath")
            .arg(&script_dir)
            .arg("-postScript")
            .arg("GhidraMcp.java")
            .arg("host=127.0.0.1")
            .arg(format!("port={port}"))
            .arg(format!("path={MCP_PATH}"))
            .arg(format!("session_id={SESSION_ID}"))
            .arg(format!("token={token}"))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .with_context(|| format!("cannot start {}", analyze_headless.display()))?;

        Ok(Self {
            child: Some(child),
            log_path,
            port,
            token,
        })
    }

    pub fn endpoint(&self) -> String {
        format!("http://127.0.0.1:{}{MCP_PATH}", self.port)
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// Waits until the MCP server answers `ping`, the process exits, or the timeout ends.
    pub fn wait_until_ready(&mut self, client: &McpClient, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child_mut()?.try_wait()? {
                bail!("Ghidra exited before the MCP server was ready ({status})");
            }
            if client.ping().is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "the MCP server was not ready after {} seconds",
                    timeout.as_secs()
                );
            }
            thread::sleep(Duration::from_secs(2));
        }
    }

    /// Waits for the process to exit by itself.
    pub fn wait_for_exit(&mut self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child_mut()?.try_wait()? {
                self.child = None;
                ensure!(status.success(), "Ghidra exited with {status}");
                return Ok(());
            }
            if Instant::now() >= deadline {
                bail!(
                    "Ghidra did not exit {} seconds after shutdown",
                    timeout.as_secs()
                );
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn log_tail(&self, lines: usize) -> String {
        let text = fs::read_to_string(&self.log_path).unwrap_or_default();
        let all: Vec<&str> = text.lines().collect();
        all[all.len().saturating_sub(lines)..].join("\n")
    }

    fn child_mut(&mut self) -> Result<&mut Child> {
        self.child.as_mut().context("Ghidra is not running")
    }
}

impl Drop for GhidraProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if matches!(child.try_wait(), Ok(None)) {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

fn analyze_headless_path(ghidra_install_dir: &Path) -> Result<PathBuf> {
    let install_dir = canonical(ghidra_install_dir, "Ghidra installation directory")?;
    let name = if cfg!(windows) {
        "analyzeHeadless.bat"
    } else {
        "analyzeHeadless"
    };
    let path = install_dir.join("support").join(name);
    ensure!(path.is_file(), "{} does not exist", path.display());
    Ok(path)
}

fn canonical(path: &Path, what: &str) -> Result<PathBuf> {
    fs::canonicalize(path).with_context(|| format!("{what} {} does not exist", path.display()))
}

fn free_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).context("no free local port")?;
    Ok(listener.local_addr()?.port())
}

fn random_token() -> String {
    let mut token = String::new();
    for round in 0..2u64 {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(round);
        hasher.write_u128(Instant::now().elapsed().as_nanos());
        hasher.write_u32(std::process::id());
        token.push_str(&format!("{:016x}", hasher.finish()));
    }
    token
}
