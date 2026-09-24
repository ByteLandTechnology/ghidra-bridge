//! `ghidra.global_variable` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::Case;
use crate::context::{find_item, items, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("global_variable.list", list),
        Case::new("global_variable.get", get),
        Case::new("global_variable.lifecycle", lifecycle),
    ]
}

fn named(name: &str) -> serde_json::Value {
    json!({"kind": "named", "name": name})
}

fn list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.global_variable",
        "list",
        json!({"filter": {"name": "g_"}, "page": {"limit": 1000}}),
    )?;
    let globals = items(&result)?;

    let banner = find_item(globals, "name", "g_banner")?;
    ensure!(
        banner["value"] == json!("ghidra-bridge-sample"),
        "wrong g_banner: {banner}"
    );
    ensure!(
        banner["data_type"] == json!({"kind": "array", "element": named("/char"), "count": 21}),
        "g_banner is not char[21]: {banner}"
    );
    let table = find_item(globals, "name", "g_lookup_table")?;
    ensure!(
        table["length"] == json!(16),
        "g_lookup_table is not 16 bytes: {table}"
    );
    let origin = find_item(globals, "name", "g_origin")?;
    ensure!(
        origin["data_type"]["name"]
            .as_str()
            .is_some_and(|name| name.ends_with("/Point")),
        "g_origin is not a Point: {origin}"
    );

    // Name filters are case-insensitive unless case_sensitive is set.
    let result = ctx.ok(
        "ghidra.global_variable",
        "list",
        json!({"filter": {"name": "G_COUNTER"}}),
    )?;
    find_item(items(&result)?, "name", "g_counter")?;
    let result = ctx.ok(
        "ghidra.global_variable",
        "list",
        json!({"filter": {"name": "G_COUNTER", "case_sensitive": true}}),
    )?;
    ensure!(
        items(&result)?.is_empty(),
        "the case-sensitive filter matched: {result}"
    );
    Ok(())
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.fact("global.g_counter")?;
    let result = ctx.ok(
        "ghidra.global_variable",
        "get",
        json!({"selector": {"address": address}}),
    )?;
    ensure!(result["name"] == json!("g_counter"), "wrong name: {result}");
    ensure!(result["data_type"] == named("/int"), "wrong type: {result}");
    ensure!(result["length"] == json!(4), "wrong length: {result}");
    ensure!(
        result["value"] == json!("0x2a"),
        "g_counter is not 42: {result}"
    );
    ensure!(
        result["namespace"] == json!("Global"),
        "wrong namespace: {result}"
    );
    Ok(())
}

/// create, patch, upsert, and delete at a free address in `.data`.
fn lifecycle(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.fact("free_data")?;
    let selector = json!({"address": address});

    let result = ctx.ok(
        "ghidra.global_variable",
        "create",
        json!({"resource": {"address": address, "name": "mcp_global", "data_type": named("int")}}),
    )?;
    ensure!(
        result["name"] == json!("mcp_global"),
        "create returned {result}"
    );
    ensure!(
        result["source_type"] == json!("USER_DEFINED"),
        "wrong source type: {result}"
    );

    // A second create at the same address conflicts.
    ctx.fail(
        "ghidra.global_variable",
        "create",
        json!({"resource": {"address": address, "name": "mcp_other", "data_type": named("int")}}),
    )?;

    let result = ctx.ok(
        "ghidra.global_variable",
        "patch",
        json!({"selector": selector, "patch": {"name": "mcp_global_renamed", "data_type": named("uint")}}),
    )?;
    ensure!(
        result["name"] == json!("mcp_global_renamed"),
        "patch did not rename: {result}"
    );
    ensure!(
        result["data_type"] == named("/uint"),
        "patch did not retype: {result}"
    );

    let pointer = json!({"kind": "pointer", "target": named("char")});
    let result = ctx.ok(
        "ghidra.global_variable",
        "upsert",
        json!({"resource": {"address": address, "name": "mcp_global_ptr", "data_type": pointer}}),
    )?;
    ensure!(
        result["length"] == json!(8),
        "a pointer must be 8 bytes: {result}"
    );
    let fetched = ctx.ok(
        "ghidra.global_variable",
        "get",
        json!({"selector": selector}),
    )?;
    ensure!(
        fetched == result,
        "get differs from upsert: {fetched} vs {result}"
    );

    let result = ctx.ok(
        "ghidra.global_variable",
        "delete",
        json!({"selector": selector, "delete_symbol": true}),
    )?;
    ensure!(
        result == json!({"deleted": true}),
        "unexpected delete result: {result}"
    );
    ctx.fail_with(
        "ghidra.global_variable",
        "get",
        json!({"selector": selector}),
        404,
        "resource_not_found",
    )?;
    let result = ctx.ok(
        "ghidra.symbol",
        "list",
        json!({"filter": {"name": "mcp_global"}}),
    )?;
    ensure!(
        items(&result)?.is_empty(),
        "delete_symbol kept the label: {result}"
    );
    Ok(())
}
