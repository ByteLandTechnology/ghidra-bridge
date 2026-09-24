//! `ghidra.help` cases.

use std::collections::BTreeSet;

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::setup::DOMAIN_TOOLS;
use super::Case;
use crate::context::TestContext;

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("help.domains", domains),
        Case::new("help.operations", operations),
        Case::new("help.operation_detail", operation_detail),
        Case::new("help.errors", errors),
    ]
}

fn help(ctx: &mut TestContext, arguments: Value) -> Result<Value> {
    let reply = ctx.client.call_tool("ghidra.help", arguments.clone())?;
    ensure!(
        !reply.is_error,
        "ghidra.help {arguments} failed: {}",
        reply.structured
    );
    ctx.mark_covered("ghidra.help");
    Ok(reply.structured)
}

fn domains(ctx: &mut TestContext) -> Result<()> {
    let result = help(ctx, json!({}))?;
    ensure!(
        result == json!({"domains": DOMAIN_TOOLS}),
        "unexpected domains: {result}"
    );
    Ok(())
}

/// Every domain lists the same operations that `tools/list` publishes.
fn operations(ctx: &mut TestContext) -> Result<()> {
    for tool in DOMAIN_TOOLS {
        let result = help(ctx, json!({"domain": tool}))?;
        ensure!(result["domain"] == json!(tool), "wrong domain in {result}");
        let listed: BTreeSet<String> = result["operations"]
            .as_array()
            .context("no operations array")?
            .iter()
            .filter_map(|operation| operation.as_str().map(|name| format!("{tool}/{name}")))
            .collect();
        let published: BTreeSet<String> = ctx
            .published
            .iter()
            .filter(|key| key.starts_with(&format!("{tool}/")))
            .cloned()
            .collect();
        ensure!(
            listed == published,
            "{tool}: help lists {listed:?}, tools/list has {published:?}"
        );
    }
    // The domain name also works without the "ghidra." prefix.
    let result = help(ctx, json!({"domain": "memory"}))?;
    ensure!(
        result["domain"] == json!("ghidra.memory"),
        "short domain name failed: {result}"
    );
    Ok(())
}

fn operation_detail(ctx: &mut TestContext) -> Result<()> {
    let result = help(ctx, json!({"domain": "ghidra.memory", "operation": "read"}))?;
    ensure!(
        result["method"] == json!("memory.read"),
        "wrong method: {result}"
    );
    ensure!(
        result["operation"] == json!("read"),
        "wrong operation: {result}"
    );
    for field in ["description", "inputSchema", "outputSchema", "effects"] {
        ensure!(result.get(field).is_some(), "help has no {field}: {result}");
    }
    ensure!(
        result["inputSchema"]["required"] == json!(["selector"]),
        "memory.read must require a selector: {}",
        result["inputSchema"]
    );

    let result = help(ctx, json!({"domain": "ghidra.bridge", "operation": "get"}))?;
    ensure!(
        result["method"] == json!("session.get"),
        "bridge get must be session.get: {result}"
    );
    Ok(())
}

fn errors(ctx: &mut TestContext) -> Result<()> {
    ctx.fail_arguments("ghidra.help", json!({"domain": "ghidra.missing"}))?;
    ctx.fail_arguments(
        "ghidra.help",
        json!({"domain": "ghidra.memory", "operation": "missing"}),
    )?;
    ctx.fail_arguments("ghidra.help", json!({"operation": "read"}))?;
    ctx.fail_arguments("ghidra.help", json!({"unknown": true}))?;
    Ok(())
}
