//! Test client for the Ghidra Bridge MCP server.
//!
//! The client starts headless Ghidra with the `GhidraMcp.java` post-script, imports a
//! binary, and calls every MCP tool operation. It checks each result against the
//! operation's output schema and against facts from the sample source code.

mod cases;
mod cli;
mod context;
mod ghidra;
mod mcp;
mod schema;

use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;

use crate::cli::Args;
use crate::context::TestContext;
use crate::ghidra::GhidraProcess;
use crate::mcp::{McpClient, DEFAULT_TOOL_PREFIX};

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(120);

struct Outcome {
    name: String,
    elapsed: Duration,
    error: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

/// Returns `Ok(true)` when every case passes.
fn run(args: &Args) -> Result<bool> {
    let binary = fs::canonicalize(&args.binary)
        .with_context(|| format!("binary {} does not exist", args.binary.display()))?;
    let work_dir = prepare_work_dir(args.work_dir.as_ref())?;
    println!("work directory: {}", work_dir.display());

    let mut ghidra = GhidraProcess::start(
        &args.ghidra_install_dir,
        &args.script_dir,
        &binary,
        &work_dir,
        args.tool_prefix.as_deref(),
    )?;
    let tool_prefix = args
        .tool_prefix
        .clone()
        .unwrap_or_else(|| DEFAULT_TOOL_PREFIX.into());
    let client = McpClient::new(
        ghidra.endpoint(),
        Some(ghidra.token().to_string()),
        tool_prefix,
    );
    println!("starting Ghidra; log: {}", ghidra.log_path().display());
    let started = Instant::now();
    if let Err(error) =
        ghidra.wait_until_ready(&client, Duration::from_secs(args.startup_timeout_secs))
    {
        eprintln!(
            "--- last lines of {} ---\n{}",
            ghidra.log_path().display(),
            ghidra.log_tail(40)
        );
        return Err(error);
    }
    println!(
        "MCP server ready at {} after {:.1}s\n",
        client.endpoint(),
        started.elapsed().as_secs_f64()
    );

    let mut ctx = TestContext::new(&client, binary);
    let mut outcomes = run_cases(&mut ctx, args.filter.as_deref());
    outcomes.push(run_shutdown(&mut ctx, &mut ghidra));

    let mut passed = report(&outcomes);
    if args.filter.is_none() {
        passed &= check_coverage(&ctx);
    }
    if passed && !args.keep_work_dir && args.work_dir.is_none() {
        drop(ghidra);
        let _ = fs::remove_dir_all(&work_dir);
    } else {
        println!("work directory kept: {}", work_dir.display());
    }
    Ok(passed)
}

fn run_cases(ctx: &mut TestContext, filter: Option<&str>) -> Vec<Outcome> {
    let mut outcomes = Vec::new();
    for case in cases::all() {
        if !case.setup && filter.is_some_and(|text| !case.name.contains(text)) {
            continue;
        }
        let outcome = run_one(case.name, || (case.run)(ctx));
        let setup_failed = case.setup && outcome.error.is_some();
        print_outcome(&outcome);
        outcomes.push(outcome);
        if setup_failed {
            eprintln!("a setup case failed; the other cases need its facts and do not run");
            break;
        }
    }
    outcomes
}

/// Stops the session through MCP and checks that Ghidra exits.
fn run_shutdown(ctx: &mut TestContext, ghidra: &mut GhidraProcess) -> Outcome {
    let outcome = run_one("bridge.shutdown", || {
        cases::shutdown(ctx)?;
        ghidra.wait_for_exit(SHUTDOWN_TIMEOUT)?;
        if ctx.client.ping().is_ok() {
            bail!("the MCP server still answers after shutdown");
        }
        Ok(())
    });
    print_outcome(&outcome);
    if outcome.error.is_some() {
        eprintln!(
            "--- last lines of {} ---\n{}",
            ghidra.log_path().display(),
            ghidra.log_tail(40)
        );
    }
    outcome
}

fn run_one(name: &str, run: impl FnOnce() -> Result<()>) -> Outcome {
    let started = Instant::now();
    let result = panic::catch_unwind(AssertUnwindSafe(run))
        .unwrap_or_else(|payload| Err(anyhow!("panic: {}", panic_message(&payload))));
    Outcome {
        name: name.to_string(),
        elapsed: started.elapsed(),
        error: result.err().map(|error| format!("{error:#}")),
    }
}

fn print_outcome(outcome: &Outcome) {
    let millis = outcome.elapsed.as_millis();
    match &outcome.error {
        None => println!("PASS  {} ({millis} ms)", outcome.name),
        Some(error) => println!(
            "FAIL  {} ({millis} ms)\n      {}",
            outcome.name,
            error.replace('\n', "\n      ")
        ),
    }
}

fn report(outcomes: &[Outcome]) -> bool {
    let failed: Vec<&Outcome> = outcomes
        .iter()
        .filter(|outcome| outcome.error.is_some())
        .collect();
    println!(
        "\n{} passed, {} failed",
        outcomes.len() - failed.len(),
        failed.len()
    );
    for outcome in &failed {
        println!("  failed: {}", outcome.name);
    }
    failed.is_empty()
}

/// Every published tool operation must have at least one valid successful call.
fn check_coverage(ctx: &TestContext) -> bool {
    let missing: Vec<&String> = ctx
        .published
        .iter()
        .filter(|key| !ctx.covered.contains(*key))
        .collect();
    let published = ctx.published.len();
    println!(
        "coverage: {}/{published} tool operations",
        published - missing.len()
    );
    for key in &missing {
        println!("  not covered: {key}");
    }
    missing.is_empty()
}

fn prepare_work_dir(requested: Option<&PathBuf>) -> Result<PathBuf> {
    // Ghidra rejects project paths with a directory name that starts with a dot.
    let path = match requested {
        Some(path) => path.clone(),
        None => {
            let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
            std::env::temp_dir().join(format!("ghidra-mcp-client-{}-{nanos}", std::process::id()))
        }
    };
    fs::create_dir_all(&path).with_context(|| format!("cannot create {}", path.display()))?;
    Ok(fs::canonicalize(&path)?)
}

fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    payload
        .downcast_ref::<&str>()
        .map(|text| text.to_string())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".to_string())
}
