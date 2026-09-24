//! `ghidra.symbol` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::Case;
use crate::context::{field_values, items, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("symbol.list", list),
        Case::new("symbol.get", get),
        Case::new("symbol.patch_function", patch_function),
        Case::new("symbol.patch_label", patch_label),
    ]
}

fn list(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.fact("global.g_counter")?;
    let result = ctx.ok(
        "ghidra.symbol",
        "list",
        json!({"filter": {"address": address}}),
    )?;
    let symbols = items(&result)?;
    ensure!(
        field_values(symbols, "name") == ["g_counter"],
        "wrong symbols at {address}: {result}"
    );
    ensure!(
        symbols[0]["type"] == json!("Label"),
        "g_counter is not a label: {result}"
    );
    ensure!(
        symbols[0]["primary"] == json!(true),
        "g_counter is not primary: {result}"
    );

    let result = ctx.ok(
        "ghidra.symbol",
        "list",
        json!({"filter": {"name": "_ints", "type": "Function"}, "page": {"limit": 1000}}),
    )?;
    let symbols = items(&result)?;
    ensure!(
        symbols
            .iter()
            .all(|symbol| symbol["type"] == json!("Function")),
        "type filter failed"
    );
    let names = field_values(symbols, "name");
    ensure!(
        names.contains(&"add_ints") && names.contains(&"multiply_ints"),
        "missing: {names:?}"
    );
    Ok(())
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let id = ctx.fact("symbol.g_counter")?;
    let result = ctx.ok("ghidra.symbol", "get", json!({"selector": {"id": id}}))?;
    ensure!(result["id"] == json!(id), "wrong id: {result}");
    ensure!(result["name"] == json!("g_counter"), "wrong name: {result}");
    ensure!(
        result["address"] == json!(ctx.fact("global.g_counter")?),
        "wrong address: {result}"
    );
    ctx.fail(
        "ghidra.symbol",
        "get",
        json!({"selector": {"id": "999999999"}}),
    )?;
    ctx.fail(
        "ghidra.symbol",
        "get",
        json!({"selector": {"id": "not-a-number"}}),
    )?;
    Ok(())
}

fn rename(ctx: &mut TestContext, id: &str, name: &str) -> Result<()> {
    let result = ctx.ok(
        "ghidra.symbol",
        "patch",
        json!({"selector": {"id": id}, "patch": {"name": name}}),
    )?;
    ensure!(
        result["name"] == json!(name),
        "rename to {name} returned {result}"
    );
    let fetched = ctx.ok("ghidra.symbol", "get", json!({"selector": {"id": id}}))?;
    ensure!(
        fetched["name"] == json!(name),
        "rename to {name} did not persist: {fetched}"
    );
    Ok(())
}

fn patch_function(ctx: &mut TestContext) -> Result<()> {
    let id = ctx.fact("symbol.multiply_ints")?;
    rename(ctx, &id, "multiply_values")?;
    let entry = ctx.entry("multiply_ints")?;
    let function = ctx.ok(
        "ghidra.function",
        "get",
        json!({"selector": {"entry": entry}}),
    )?;
    ensure!(
        function["name"] == json!("multiply_values"),
        "the function was not renamed"
    );
    rename(ctx, &id, "multiply_ints")
}

/// Renaming a label keeps its symbol id, like renaming a function.
fn patch_label(ctx: &mut TestContext) -> Result<()> {
    let id = ctx.fact("symbol.g_counter")?;
    rename(ctx, &id, "g_counter_renamed")?;

    // The label stays the primary name of the global variable at the same address.
    let address = ctx.fact("global.g_counter")?;
    let global = ctx.ok(
        "ghidra.global_variable",
        "get",
        json!({"selector": {"address": address}}),
    )?;
    ensure!(
        global["name"] == json!("g_counter_renamed"),
        "the global variable was not renamed: {global}"
    );
    let result = ctx.ok("ghidra.symbol", "get", json!({"selector": {"id": id}}))?;
    ensure!(
        result["address"] == json!(address) && result["primary"] == json!(true),
        "the renamed label moved or lost primary state: {result}"
    );

    // Ghidra rejects a symbol name with whitespace, and the label keeps its name.
    ctx.fail(
        "ghidra.symbol",
        "patch",
        json!({"selector": {"id": id}, "patch": {"name": "bad name"}}),
    )?;
    let result = ctx.ok("ghidra.symbol", "get", json!({"selector": {"id": id}}))?;
    ensure!(
        result["name"] == json!("g_counter_renamed"),
        "a rejected rename changed the label: {result}"
    );
    rename(ctx, &id, "g_counter")
}
