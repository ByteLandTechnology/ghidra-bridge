//! Setup cases. They read the tool catalog and resolve names in the sample binary, so no
//! other case needs a hard-coded address.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{find_item, items, text, TestContext};

/// Domain tools that `tools/list` must publish, after `ghidra.help`.
pub const DOMAIN_TOOLS: [&str; 14] = [
    "ghidra.bridge",
    "ghidra.program",
    "ghidra.address",
    "ghidra.memory",
    "ghidra.listing",
    "ghidra.global_variable",
    "ghidra.function",
    "ghidra.analysis",
    "ghidra.decompilation",
    "ghidra.symbol",
    "ghidra.reference",
    "ghidra.comment",
    "ghidra.data_type",
    "ghidra.batch",
];

/// Functions that the sample defines.
pub const SAMPLE_FUNCTIONS: [&str; 9] = [
    "main",
    "add_ints",
    "multiply_ints",
    "apply_op",
    "sum_points",
    "bump_counter",
    "checksum_bytes",
    "color_name",
    "cpp_total_area",
];

/// Global variables that the sample defines.
pub const SAMPLE_GLOBALS: [&str; 4] = ["g_counter", "g_banner", "g_lookup_table", "g_origin"];

pub fn cases() -> Vec<Case> {
    vec![
        Case::setup("setup.tool_catalog", tool_catalog),
        Case::setup("setup.sample_functions", sample_functions),
        Case::setup("setup.sample_globals", sample_globals),
        Case::setup("setup.memory_layout", memory_layout),
    ]
}

/// Reads `tools/list` and records every published tool operation.
fn tool_catalog(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.client.rpc("tools/list", json!({}))?;
    let tools = result
        .get("tools")
        .and_then(Value::as_array)
        .context("tools/list has no tools")?;
    let names: Vec<&str> = tools
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    let mut expected = vec!["ghidra.help"];
    expected.extend(DOMAIN_TOOLS);
    ensure!(
        names == expected,
        "tools/list returned {names:?}, expected {expected:?}"
    );

    for tool in tools {
        let name = text(tool, "/name")?;
        ensure!(
            tool.get("description").and_then(Value::as_str).is_some(),
            "{name} has no description"
        );
        ensure!(
            tool.get("annotations").is_some_and(Value::is_object),
            "{name} has no annotations"
        );
        if name == "ghidra.help" {
            ctx.published.insert(name.to_string());
            continue;
        }
        ensure!(
            tool.get("outputSchema").is_some(),
            "{name} has no outputSchema"
        );
        let variants = tool
            .pointer("/inputSchema/oneOf")
            .and_then(Value::as_array)
            .with_context(|| format!("{name} inputSchema has no oneOf"))?;
        ensure!(!variants.is_empty(), "{name} has no operations");
        for variant in variants {
            let operation = text(variant, "/properties/operation/const")?;
            ctx.published.insert(format!("{name}/{operation}"));
        }
    }
    // 52 methods in 14 domain tools, plus ghidra.help.
    ensure!(
        ctx.published.len() == 53,
        "tools/list publishes {} entries",
        ctx.published.len()
    );
    Ok(())
}

/// Resolves the entry point and body of every sample function.
fn sample_functions(ctx: &mut TestContext) -> Result<()> {
    for name in SAMPLE_FUNCTIONS {
        let result = ctx.ok(
            "ghidra.function",
            "list",
            json!({"filter": {"name": name}, "projection": {"fields": ["name", "entry", "body"]}}),
        )?;
        let function = find_item(items(&result)?, "name", name)?;
        ctx.set_fact(&format!("entry.{name}"), text(function, "/entry")?);
        ctx.set_fact(&format!("body_end.{name}"), text(function, "/body/end")?);
    }

    // The first call in main calls bump_counter.
    let main = ctx.entry("main")?;
    let main_end = ctx.fact("body_end.main")?;
    let result = ctx.ok(
        "ghidra.listing",
        "instruction.list",
        json!({
            "scan": {"range": {"start": main, "end": main_end}},
            "page": {"limit": 1000},
            "projection": {"fields": ["address", "mnemonic"]},
        }),
    )?;
    let call = find_item(items(&result)?, "mnemonic", "CALL")?;
    ctx.set_fact("call.main.first", text(call, "/address")?);
    Ok(())
}

/// Resolves the address of every sample global and the symbol id of `g_counter`.
fn sample_globals(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.global_variable",
        "list",
        json!({"filter": {"name": "g_"}, "page": {"limit": 1000}}),
    )?;
    let globals = items(&result)?;
    for name in SAMPLE_GLOBALS {
        let global = find_item(globals, "name", name)?;
        ctx.set_fact(&format!("global.{name}"), text(global, "/address")?);
    }

    let result = ctx.ok(
        "ghidra.symbol",
        "list",
        json!({"filter": {"name": "g_counter"}}),
    )?;
    let symbol = find_item(items(&result)?, "name", "g_counter")?;
    ctx.set_fact("symbol.g_counter", text(symbol, "/id")?);

    let result = ctx.ok(
        "ghidra.symbol",
        "list",
        json!({"filter": {"name": "multiply_ints"}}),
    )?;
    let symbol = find_item(items(&result)?, "name", "multiply_ints")?;
    ctx.set_fact("symbol.multiply_ints", text(symbol, "/id")?);
    Ok(())
}

/// Records the image base and the memory blocks that the cases use.
fn memory_layout(ctx: &mut TestContext) -> Result<()> {
    let program = ctx.ok("ghidra.program", "get", json!({}))?;
    ctx.set_fact("image_base", text(&program, "/image_base")?);

    let result = ctx.ok(
        "ghidra.memory",
        "block.list",
        json!({"page": {"limit": 1000}}),
    )?;
    let blocks = items(&result)?;
    for name in [".text", ".data", ".bss"] {
        let block = find_item(blocks, "name", name)?;
        let key = name.trim_start_matches('.');
        ctx.set_fact(&format!("block.{key}.start"), text(block, "/start")?);
        ctx.set_fact(&format!("block.{key}.end"), text(block, "/end")?);
    }

    // The global variable cases create data at the start of .data. It must be free.
    let free = ctx.fact("block.data.start")?;
    ctx.fail_with(
        "ghidra.global_variable",
        "get",
        json!({"selector": {"address": free}}),
        404,
        "resource_not_found",
    )
    .context("the start of .data must not hold a global variable")?;
    ctx.set_fact("free_data", free);
    Ok(())
}
