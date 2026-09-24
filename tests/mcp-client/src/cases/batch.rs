//! `ghidra.batch` cases.

use anyhow::{ensure, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{expect_error, items, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("batch.per_item", per_item),
        Case::new("batch.all_or_none_commit", all_or_none_commit),
        Case::new("batch.all_or_none_rollback", all_or_none_rollback),
        Case::new("batch.validation", validation),
    ]
}

fn comment_item(id: &str, address: &str, text: &str) -> Value {
    json!({
        "id": id,
        "method": "comment.create",
        "arguments": {"resource": {"address": address, "type": "pre", "text": text}},
    })
}

fn comment_exists(ctx: &mut TestContext, address: &str) -> Result<bool> {
    let reply = ctx.client.call_tool(
        "ghidra.comment",
        json!({"operation": "get", "params": {"selector": {"address": address, "type": "pre"}}}),
    )?;
    if reply.is_error {
        expect_error(&reply.structured, 404, "comment_not_found")?;
    }
    Ok(!reply.is_error)
}

fn delete_comment(ctx: &mut TestContext, address: &str) -> Result<()> {
    ctx.ok(
        "ghidra.comment",
        "delete",
        json!({"selector": {"address": address, "type": "pre"}}),
    )?;
    Ok(())
}

/// A failed item does not stop the batch, and the default mode is per_item.
fn per_item(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.entry("apply_op")?;
    let result = ctx.ok(
        "ghidra.batch",
        "execute",
        json!({"items": [
            comment_item("first", &address, "batch one"),
            comment_item("duplicate", &address, "batch two"),
            {"id": "read", "method": "program.get", "arguments": {"projection": {"fields": ["name"]}}},
        ]}),
    )?;
    let rows = items(&result)?;
    ensure!(rows.len() == 3, "expected three rows: {result}");
    ensure!(
        rows[0]["id"] == json!("first") && rows[0]["result"]["text"] == json!("batch one"),
        "row 0: {result}"
    );
    ensure!(
        rows[1]["id"] == json!("duplicate") && rows[1]["error"]["code"] == json!("comment_exists"),
        "row 1: {result}"
    );
    ensure!(
        rows[2]["id"] == json!("read") && rows[2]["result"].get("name").is_some(),
        "row 2: {result}"
    );
    ensure!(
        comment_exists(ctx, &address)?,
        "the successful item was not kept"
    );
    delete_comment(ctx, &address)
}

fn all_or_none_commit(ctx: &mut TestContext) -> Result<()> {
    let first = ctx.entry("apply_op")?;
    let second = ctx.entry("color_name")?;
    let result = ctx.ok(
        "ghidra.batch",
        "execute",
        json!({"transaction_mode": "all_or_none", "items": [
            comment_item("a", &first, "atomic one"),
            comment_item("b", &second, "atomic two"),
        ]}),
    )?;
    ensure!(items(&result)?.len() == 2, "expected two rows: {result}");
    ensure!(
        comment_exists(ctx, &first)? && comment_exists(ctx, &second)?,
        "the batch did not commit"
    );
    delete_comment(ctx, &first)?;
    delete_comment(ctx, &second)
}

/// A failure rolls back the earlier items of the batch.
fn all_or_none_rollback(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.entry("apply_op")?;
    let error = ctx.fail_with(
        "ghidra.batch",
        "execute",
        json!({"transaction_mode": "all_or_none", "items": [
            comment_item("first", &address, "rolled back"),
            comment_item("second", &address, "duplicate"),
        ]}),
        409,
        "batch_rolled_back",
    )?;
    ensure!(
        error["details"]["failed_item"] == json!("second"),
        "wrong failed item: {error}"
    );
    ensure!(
        error["details"]["cause"]["code"] == json!("comment_exists"),
        "wrong cause: {error}"
    );
    ensure!(
        !comment_exists(ctx, &address)?,
        "the first item was not rolled back"
    );
    Ok(())
}

/// Prevalidation rejects the whole batch before any item runs.
fn validation(ctx: &mut TestContext) -> Result<()> {
    let address = ctx.entry("apply_op")?;
    for (method, arguments) in [
        ("program.save", json!({})),
        ("analysis.start", json!({})),
        ("session.shutdown", json!({})),
        ("batch.execute", json!({"items": []})),
        ("interface.get", json!({})),
    ] {
        let error = ctx.fail_with(
            "ghidra.batch",
            "execute",
            json!({"items": [
                comment_item("valid", &address, "never runs"),
                {"id": "blocked", "method": method, "arguments": arguments},
            ]}),
            400,
            "validation_failed",
        )?;
        let violations = error["details"]["violations"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        ensure!(
            violations
                .iter()
                .any(|violation| violation["target"] == json!("/items/1/method")),
            "{method} was not rejected at /items/1/method: {error}"
        );
    }

    let error = ctx.fail_with(
        "ghidra.batch",
        "execute",
        json!({"items": [comment_item("same", &address, "one"), comment_item("same", &address, "two")]}),
        400,
        "validation_failed",
    )?;
    ensure!(
        error.to_string().contains("duplicate_id"),
        "no duplicate_id violation: {error}"
    );

    let error = ctx.fail_with(
        "ghidra.batch",
        "execute",
        json!({"items": [{"id": "bad", "method": "comment.create", "arguments": {"resource": {}}}]}),
        400,
        "validation_failed",
    )?;
    ensure!(
        error.to_string().contains("/items/0/arguments"),
        "no argument violation: {error}"
    );

    ctx.fail_with(
        "ghidra.batch",
        "execute",
        json!({"items": []}),
        400,
        "validation_failed",
    )?;
    ensure!(
        !comment_exists(ctx, &address)?,
        "a rejected batch ran an item"
    );
    Ok(())
}
