//! `ghidra.listing` cases: code units, data units, instructions, and flow overrides.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{address_offset, find_item, items, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("listing.code_unit_list", code_unit_list),
        Case::new("listing.code_unit_paging", code_unit_paging),
        Case::new("listing.data_unit_list", data_unit_list),
        Case::new(
            "listing.data_unit_list_uninitialized",
            data_unit_list_uninitialized,
        ),
        Case::new("listing.instruction_get", instruction_get),
        Case::new("listing.instruction_list", instruction_list),
        Case::new("listing.flow_override", flow_override),
    ]
}

fn main_range(ctx: &TestContext) -> Result<Value> {
    Ok(json!({"start": ctx.entry("main")?, "end": ctx.fact("body_end.main")?}))
}

fn code_unit_list(ctx: &mut TestContext) -> Result<()> {
    let range = main_range(ctx)?;
    let result = ctx.ok(
        "ghidra.listing",
        "code_unit.list",
        json!({"scan": {"range": range}, "page": {"limit": 1000}}),
    )?;
    let units = items(&result)?;
    ensure!(!units.is_empty(), "main has no code units");
    ensure!(
        units[0]["address"] == range["start"],
        "the first unit is not the entry: {}",
        units[0]
    );
    ensure!(
        result["scan"]["complete"] == json!(true),
        "the scan is incomplete: {result}"
    );
    ensure!(
        result["scan"]["stop_reason"] == json!("completed"),
        "wrong stop reason: {result}"
    );
    ensure!(
        result.get("next_cursor").is_none(),
        "a complete scan has a cursor: {result}"
    );

    for kind in ["instruction", "data"] {
        let result = ctx.ok(
            "ghidra.listing",
            "code_unit.list",
            json!({"filter": {"kind": kind}, "scan": {"range": range}, "page": {"limit": 1000}}),
        )?;
        let units = items(&result)?;
        ensure!(
            units.iter().all(|unit| unit["kind"] == json!(kind)),
            "the kind={kind} filter returned other units"
        );
        if kind == "instruction" {
            ensure!(!units.is_empty(), "main has no instructions");
        }
    }
    Ok(())
}

/// A cursor resumes after the last item of the previous page.
fn code_unit_paging(ctx: &mut TestContext) -> Result<()> {
    let range = main_range(ctx)?;
    let request = |cursor: Option<&str>| {
        let mut params = json!({
            "scan": {"range": range},
            "page": {"limit": 5},
            "projection": {"fields": ["address"]},
        });
        if let Some(cursor) = cursor {
            params["page"]["cursor"] = json!(cursor);
        }
        params
    };
    let first = ctx.ok("ghidra.listing", "code_unit.list", request(None))?;
    ensure!(
        items(&first)?.len() == 5,
        "the first page does not have 5 items: {first}"
    );
    ensure!(
        first["scan"]["stop_reason"] == json!("limit"),
        "wrong stop reason: {first}"
    );
    let cursor = text(&first, "/next_cursor")?.to_string();
    let second = ctx.ok("ghidra.listing", "code_unit.list", request(Some(&cursor)))?;
    let last_first = address_offset(text(&items(&first)?[4], "/address")?)?;
    let first_second = address_offset(text(&items(&second)?[0], "/address")?)?;
    ensure!(
        first_second > last_first,
        "the second page overlaps the first page"
    );

    ctx.fail(
        "ghidra.listing",
        "code_unit.list",
        json!({"page": {"cursor": "not-a-cursor"}}),
    )?;
    Ok(())
}

fn data_unit_list(ctx: &mut TestContext) -> Result<()> {
    let range = json!({"start": ctx.fact("block.data.start")?, "end": ctx.fact("block.data.end")?});
    let result = ctx.ok(
        "ghidra.listing",
        "data_unit.list",
        json!({"scan": {"range": range}, "page": {"limit": 1000}}),
    )?;
    let counter = find_item(items(&result)?, "address", &ctx.fact("global.g_counter")?)?;
    ensure!(
        counter["length"] == json!(4),
        "g_counter is not 4 bytes: {counter}"
    );
    ensure!(
        counter["data_type"] == json!({"kind": "named", "name": "/int"}),
        "g_counter is not an int: {counter}"
    );
    ensure!(
        counter["bytes"]["data"] == json!("2a000000"),
        "g_counter is not 42: {counter}"
    );
    Ok(())
}

/// Data in `.bss` has no bytes in the file. Listing it must work and omit `bytes`.
fn data_unit_list_uninitialized(ctx: &mut TestContext) -> Result<()> {
    let range = json!({"start": ctx.fact("block.bss.start")?, "end": ctx.fact("block.bss.end")?});
    let origin = ctx.fact("global.g_origin")?;
    for operation in ["data_unit.list", "code_unit.list"] {
        let result = ctx.ok(
            "ghidra.listing",
            operation,
            json!({"scan": {"range": range}, "page": {"limit": 1000}}),
        )?;
        let unit = find_item(items(&result)?, "address", &origin)?;
        ensure!(
            unit["length"] == json!(8),
            "{operation}: g_origin is not 8 bytes: {unit}"
        );
        ensure!(
            unit.get("bytes").is_none(),
            "{operation}: uninitialized data must not have bytes: {unit}"
        );
    }
    Ok(())
}

fn instruction_get(ctx: &mut TestContext) -> Result<()> {
    let main = ctx.entry("main")?;
    let result = ctx.ok(
        "ghidra.listing",
        "instruction.get",
        json!({"selector": {"address": main}}),
    )?;
    ensure!(
        result["mnemonic"] == json!("PUSH"),
        "main does not start with PUSH: {result}"
    );
    ensure!(
        result["operands"] == json!(["RBP"]),
        "main does not push RBP: {result}"
    );
    ensure!(
        result["bytes"]["data"] == json!("55"),
        "wrong bytes: {result}"
    );
    ensure!(
        result["flow_override"] == json!("none"),
        "unexpected flow override: {result}"
    );

    let call = ctx.fact("call.main.first")?;
    let result = ctx.ok(
        "ghidra.listing",
        "instruction.get",
        json!({"selector": {"address": call}}),
    )?;
    ensure!(
        result["flow_type"] == json!("UNCONDITIONAL_CALL"),
        "not a call: {result}"
    );

    let banner = ctx.fact("global.g_banner")?;
    ctx.fail(
        "ghidra.listing",
        "instruction.get",
        json!({"selector": {"address": banner}}),
    )?;
    Ok(())
}

fn instruction_list(ctx: &mut TestContext) -> Result<()> {
    let range = main_range(ctx)?;
    let result = ctx.ok(
        "ghidra.listing",
        "instruction.list",
        json!({"scan": {"range": range}, "page": {"limit": 1000}}),
    )?;
    let instructions = items(&result)?;
    ensure!(
        instructions[0]["address"] == range["start"],
        "the list does not start at main"
    );
    let last = instructions.last().context("no instructions")?;
    ensure!(
        last["mnemonic"] == json!("RET"),
        "main does not end with RET: {last}"
    );
    let calls = instructions
        .iter()
        .filter(|item| item["mnemonic"] == json!("CALL"))
        .count();
    ensure!(calls >= 7, "main has {calls} calls, expected at least 7");
    Ok(())
}

fn flow_override(ctx: &mut TestContext) -> Result<()> {
    let call = ctx.fact("call.main.first")?;
    let main = ctx.entry("main")?;
    let function = json!({"kind": "function", "entry": main});

    let result = ctx.ok(
        "ghidra.listing",
        "flow_override.patch",
        json!({"selector": {"kind": "address", "address": call}, "patch": {"flow_override": "branch"}}),
    )?;
    let changed = find_item(items(&result)?, "address", &call)?;
    ensure!(
        changed["flow_override"] == json!("branch"),
        "override not set: {changed}"
    );
    ensure!(
        changed["flow_type"] == json!("UNCONDITIONAL_JUMP"),
        "flow not changed: {changed}"
    );

    let result = ctx.ok(
        "ghidra.listing",
        "flow_override.list",
        json!({"filter": {"selector": function}}),
    )?;
    let listed = items(&result)?;
    ensure!(listed.len() == 1, "expected one override in main: {result}");
    ensure!(
        listed[0]["address"] == json!(call),
        "wrong override: {result}"
    );

    // A guarded write does nothing when the current override is not expected.
    ctx.fail(
        "ghidra.listing",
        "flow_override.patch",
        json!({
            "selector": {"kind": "address", "address": call},
            "patch": {"flow_override": "none", "expected_flow_overrides": ["call_return"]},
        }),
    )?;

    ctx.ok(
        "ghidra.listing",
        "flow_override.patch",
        json!({
            "selector": function,
            "patch": {"flow_override": "none", "expected_flow_overrides": ["branch"]},
        }),
    )?;
    let result = ctx.ok(
        "ghidra.listing",
        "flow_override.list",
        json!({"filter": {"selector": function, "flow_overrides": ["branch", "call", "call_return", "return"]}}),
    )?;
    ensure!(
        items(&result)?.is_empty(),
        "the override was not cleared: {result}"
    );
    let result = ctx.ok(
        "ghidra.listing",
        "instruction.get",
        json!({"selector": {"address": call}}),
    )?;
    ensure!(
        result["flow_override"] == json!("none"),
        "the override remains: {result}"
    );
    Ok(())
}
