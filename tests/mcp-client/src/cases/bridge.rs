//! `ghidra.bridge` cases.

use anyhow::{ensure, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::TestContext;
use crate::ghidra::SESSION_ID;

pub fn cases() -> Vec<Case> {
    vec![Case::new("bridge.get", get)]
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok("ghidra.bridge", "get", json!({}))?;
    ensure!(
        result["id"] == json!(SESSION_ID),
        "wrong session id: {result}"
    );
    ensure!(
        result["status"] == json!("active"),
        "session is not active: {result}"
    );
    ensure!(
        result["program_name"] == json!(binary_name(ctx)),
        "wrong program: {result}"
    );

    // A projection keeps only the requested fields and the identity fields.
    let result = ctx.ok(
        "ghidra.bridge",
        "get",
        json!({"projection": {"fields": ["status"]}}),
    )?;
    let keys: Vec<&String> = result
        .as_object()
        .map(|map| map.keys().collect())
        .unwrap_or_default();
    ensure!(
        keys.len() == 2 && result.get("status").is_some(),
        "projection failed: {result}"
    );
    Ok(())
}

/// Stops the session. The runner calls this case last.
pub fn shutdown(ctx: &mut TestContext) -> Result<Value> {
    let result = ctx.ok("ghidra.bridge", "shutdown", json!({}))?;
    ensure!(
        result == json!({"shutdown": true}),
        "unexpected shutdown result: {result}"
    );
    Ok(result)
}

pub fn binary_name(ctx: &TestContext) -> String {
    ctx.binary
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default()
}
