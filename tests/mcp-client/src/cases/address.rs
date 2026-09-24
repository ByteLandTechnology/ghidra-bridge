//! `ghidra.address` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::Case;
use crate::context::{find_item, items, offset_address, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("address.space_list", space_list),
        Case::new("address.resolve", resolve),
    ]
}

fn space_list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.address",
        "space.list",
        json!({"page": {"limit": 1000}}),
    )?;
    let spaces = items(&result)?;
    let ram = find_item(spaces, "name", "ram")?;
    ensure!(
        ram["default"] == json!(true),
        "ram is not the default space: {ram}"
    );
    ensure!(ram["size"] == json!(64), "ram is not a 64-bit space: {ram}");

    // Paging returns every space exactly once.
    let mut paged = Vec::new();
    let mut params = json!({"page": {"limit": 1}, "projection": {"fields": ["name"]}});
    loop {
        let page = ctx.ok("ghidra.address", "space.list", params.clone())?;
        let page_items = items(&page)?;
        ensure!(
            page_items.len() <= 1,
            "page limit 1 returned {}",
            page_items.len()
        );
        paged.extend(page_items.iter().map(|item| item["name"].clone()));
        match page.get("next_cursor").and_then(|cursor| cursor.as_str()) {
            Some(cursor) => params["page"]["cursor"] = json!(cursor),
            None => break,
        }
        ensure!(
            paged.len() <= spaces.len(),
            "paging returned more spaces than one page"
        );
    }
    let all: Vec<_> = spaces.iter().map(|item| item["name"].clone()).collect();
    ensure!(paged == all, "paged spaces {paged:?} differ from {all:?}");
    Ok(())
}

fn resolve(ctx: &mut TestContext) -> Result<()> {
    let main = ctx.entry("main")?;
    let inside = offset_address(&main, 4)?;
    let result = ctx.ok(
        "ghidra.address",
        "resolve",
        json!({"selector": {"address": inside}}),
    )?;
    ensure!(
        result["address"] == json!(inside),
        "wrong address: {result}"
    );
    ensure!(
        result["valid"] == json!(true),
        "address is not valid: {result}"
    );
    ensure!(
        result["in_memory"] == json!(true),
        "address is not in memory: {result}"
    );
    ensure!(
        result["function"] == json!({"entry": main, "name": "main"}),
        "wrong function: {result}"
    );
    ensure!(
        text(&result, "/memory_block/name")? == ".text",
        "wrong block: {result}"
    );

    let counter = ctx.fact("global.g_counter")?;
    let result = ctx.ok(
        "ghidra.address",
        "resolve",
        json!({"selector": {"address": counter}}),
    )?;
    ensure!(
        text(&result, "/symbol/name")? == "g_counter",
        "wrong symbol: {result}"
    );
    ensure!(
        result.get("function").is_none(),
        "data must not have a function: {result}"
    );

    ctx.fail(
        "ghidra.address",
        "resolve",
        json!({"selector": {"address": "not-an-address"}}),
    )?;
    Ok(())
}
