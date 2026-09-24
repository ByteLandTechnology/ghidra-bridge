use std::path::PathBuf;

use clap::Parser;

/// Runs every Ghidra Bridge MCP tool against a binary loaded in headless Ghidra.
///
/// The caller supplies every path. The tool does not search for Ghidra, the bridge
/// scripts, or the sample binary.
#[derive(Debug, Parser)]
#[command(name = "ghidra-mcp-client", version)]
pub struct Args {
    /// Ghidra installation directory. It must contain support/analyzeHeadless.
    #[arg(long, value_name = "DIR")]
    pub ghidra_install_dir: PathBuf,

    /// Directory that holds GhidraMcp.java and ghidra-bridge.jar
    /// (the output of `./gradlew buildGhidraScript`).
    #[arg(long, value_name = "DIR")]
    pub script_dir: PathBuf,

    /// Binary to import into Ghidra. Build tests/sample to get the expected binary.
    #[arg(long, value_name = "PATH")]
    pub binary: PathBuf,

    /// Directory for the Ghidra project and log. The default is a new directory in the
    /// system temporary directory.
    #[arg(long, value_name = "DIR")]
    pub work_dir: Option<PathBuf>,

    /// Keep the work directory after the run.
    #[arg(long)]
    pub keep_work_dir: bool,

    /// Maximum time for import, auto-analysis, and MCP server startup.
    #[arg(long, value_name = "SECONDS", default_value_t = 600)]
    pub startup_timeout_secs: u64,

    /// Run only the cases whose name contains this text. Setup cases and the final
    /// shutdown case always run. The coverage check is skipped when a filter is set.
    #[arg(long, value_name = "TEXT")]
    pub filter: Option<String>,
}
