//! `ghidra.analysis` cases.

use std::thread;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{expect_error, text, TestContext};

const ANALYSIS_TIMEOUT: Duration = Duration::from_secs(600);

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("analysis.get", get),
        Case::new("analysis.start", start),
    ]
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok("ghidra.analysis", "get", json!({}))?;
    ensure!(
        result["analyzed"] == json!(true),
        "the program is not analyzed: {result}"
    );
    ensure!(
        result["status"] != json!("running"),
        "analysis is still running: {result}"
    );
    Ok(())
}

/// Starts analysis, checks that writes are blocked while it runs, and waits for the end.
fn start(ctx: &mut TestContext) -> Result<()> {
    let started = ctx.ok("ghidra.analysis", "start", json!({}))?;
    ensure!(started["kind"] == json!("bridge"), "wrong kind: {started}");
    let task = text(&started, "/task_id")?.to_string();

    // Analysis of the small sample can end quickly. Check the conflicts only while the
    // bridge still reports that it runs.
    let address = ctx.entry("color_name")?;
    let write = json!({
        "operation": "create",
        "params": {"resource": {"address": address, "type": "eol", "text": "during analysis"}},
    });
    let reply = ctx.client.call_tool("ghidra.comment", write)?;
    if reply.is_error {
        expect_error(&reply.structured, 409, "analysis_in_progress")?;
        let reply = ctx.client.call_tool(
            "ghidra.analysis",
            json!({"operation": "start", "params": {}}),
        )?;
        if reply.is_error {
            expect_error(&reply.structured, 409, "analysis_already_running")?;
        }
    } else if status(ctx)?["status"] == json!("running") {
        bail!("a write succeeded while analysis was running");
    } else {
        ctx.ok(
            "ghidra.comment",
            "delete",
            json!({"selector": {"address": address, "type": "eol"}}),
        )?;
    }

    // Reads stay available while analysis runs.
    ctx.ok(
        "ghidra.program",
        "get",
        json!({"projection": {"fields": ["name"]}}),
    )?;

    let finished = wait_for_end(ctx)?;
    ensure!(
        finished["status"] == json!("completed"),
        "analysis ended with {finished}"
    );
    ensure!(finished["task_id"] == json!(task), "wrong task: {finished}");
    ensure!(
        finished.get("finished_at").is_some(),
        "no finished_at: {finished}"
    );

    // The task checks analyzer names when it runs, so an unknown name fails the task.
    let started = ctx.ok(
        "ghidra.analysis",
        "start",
        json!({"analyzers": ["No Such Analyzer"]}),
    )?;
    let finished = wait_for_end(ctx)?;
    ensure!(
        finished["task_id"] == started["task_id"],
        "wrong task: {finished}"
    );
    ensure!(
        finished["status"] == json!("failed"),
        "an unknown analyzer did not fail: {finished}"
    );

    // An empty analyzer list is rejected at once.
    ctx.fail("ghidra.analysis", "start", json!({"analyzers": []}))?;
    Ok(())
}

fn wait_for_end(ctx: &mut TestContext) -> Result<Value> {
    let deadline = Instant::now() + ANALYSIS_TIMEOUT;
    loop {
        let current = status(ctx)?;
        if current["status"] != json!("running") {
            return Ok(current);
        }
        if Instant::now() >= deadline {
            bail!(
                "analysis did not finish in {} seconds",
                ANALYSIS_TIMEOUT.as_secs()
            );
        }
        thread::sleep(Duration::from_millis(500));
    }
}

fn status(ctx: &mut TestContext) -> Result<Value> {
    ctx.ok("ghidra.analysis", "get", json!({}))
}
