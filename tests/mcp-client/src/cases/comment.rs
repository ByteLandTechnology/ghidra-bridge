//! `ghidra.comment` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::Case;
use crate::context::{find_item, items, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("comment.lifecycle", lifecycle),
        Case::new("comment.list", list),
    ]
}

/// create, get, patch, upsert, and delete one comment of each type.
fn lifecycle(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.entry("checksum_bytes")?;
    for kind in ["eol", "plate", "post", "pre", "repeatable"] {
        let selector = json!({"address": address, "type": kind});
        let resource = json!({"address": address, "type": kind, "text": format!("{kind} one")});

        let result = ctx.ok("ghidra.comment", "create", json!({"resource": resource}))?;
        ensure!(result == resource, "create returned {result}");
        ctx.fail_with(
            "ghidra.comment",
            "create",
            json!({"resource": resource}),
            409,
            "comment_exists",
        )?;

        let result = ctx.ok("ghidra.comment", "get", json!({"selector": selector}))?;
        ensure!(result == resource, "get returned {result}");

        let result = ctx.ok(
            "ghidra.comment",
            "patch",
            json!({"selector": selector, "patch": {"text": format!("{kind} two")}}),
        )?;
        ensure!(
            result["text"] == json!(format!("{kind} two")),
            "patch returned {result}"
        );

        let replaced = json!({"address": address, "type": kind, "text": format!("{kind} three")});
        let result = ctx.ok("ghidra.comment", "upsert", json!({"resource": replaced}))?;
        ensure!(result == replaced, "upsert returned {result}");

        let result = ctx.ok("ghidra.comment", "delete", json!({"selector": selector}))?;
        ensure!(
            result == json!({"deleted": true}),
            "delete returned {result}"
        );
        ctx.fail_with(
            "ghidra.comment",
            "get",
            json!({"selector": selector}),
            404,
            "comment_not_found",
        )?;
        ctx.fail_with(
            "ghidra.comment",
            "patch",
            json!({"selector": selector, "patch": {"text": "missing"}}),
            404,
            "comment_not_found",
        )?;
    }

    // upsert also creates a missing comment.
    let resource = json!({"address": address, "type": "pre", "text": "created by upsert"});
    ensure!(
        ctx.ok("ghidra.comment", "upsert", json!({"resource": resource}))? == resource,
        "upsert create"
    );
    ctx.ok(
        "ghidra.comment",
        "delete",
        json!({"selector": {"address": address, "type": "pre"}}),
    )?;
    Ok(())
}

fn list(ctx: &mut TestContext) -> Result<()> {
    let first = ctx.entry("add_ints")?;
    let second = ctx.entry("multiply_ints")?;
    for (address, text) in [(&first, "mcp list one"), (&second, "mcp list two")] {
        ctx.ok(
            "ghidra.comment",
            "create",
            json!({"resource": {"address": address, "type": "plate", "text": text}}),
        )?;
    }

    let result = ctx.ok(
        "ghidra.comment",
        "list",
        json!({"filter": {"text": "mcp list", "type": "plate"}, "page": {"limit": 1000}}),
    )?;
    let comments = items(&result)?;
    ensure!(comments.len() == 2, "expected two comments: {result}");
    find_item(comments, "address", &first)?;
    find_item(comments, "address", &second)?;

    // filter.address is the start of the scan, so the first match is at that address.
    let result = ctx.ok(
        "ghidra.comment",
        "list",
        json!({"filter": {"address": second, "type": "plate"}, "page": {"limit": 1}}),
    )?;
    let comments = items(&result)?;
    ensure!(
        comments.len() == 1 && comments[0]["text"] == json!("mcp list two"),
        "address filter: {result}"
    );

    // A range of one address selects the comments at that address only.
    let result = ctx.ok(
        "ghidra.comment",
        "list",
        json!({"scan": {"range": {"start": first, "end": first}}}),
    )?;
    let comments = items(&result)?;
    ensure!(
        comments.len() == 1 && comments[0]["text"] == json!("mcp list one"),
        "range: {result}"
    );

    for address in [&first, &second] {
        ctx.ok(
            "ghidra.comment",
            "delete",
            json!({"selector": {"address": address, "type": "plate"}}),
        )?;
    }
    let result = ctx.ok(
        "ghidra.comment",
        "list",
        json!({"filter": {"text": "mcp list"}}),
    )?;
    ensure!(
        items(&result)?.is_empty(),
        "comments remain after delete: {result}"
    );
    Ok(())
}
