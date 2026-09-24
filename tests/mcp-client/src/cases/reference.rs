//! `ghidra.reference` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::Case;
use crate::context::{address_offset, items, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("reference.list_to", list_to),
        Case::new("reference.list_from", list_from),
    ]
}

/// `bump_counter` reads and writes `g_counter`.
fn list_to(ctx: &mut TestContext) -> Result<()> {
    let counter = ctx.fact("global.g_counter")?;
    let result = ctx.ok(
        "ghidra.reference",
        "list",
        json!({"filter": {"direction": "to", "to": counter}, "page": {"limit": 1000}}),
    )?;
    let references = items(&result)?;
    ensure!(
        references
            .iter()
            .all(|reference| reference["to"] == json!(counter)),
        "wrong targets"
    );

    let start = address_offset(&ctx.entry("bump_counter")?)?;
    let end = address_offset(&ctx.fact("body_end.bump_counter")?)?;
    let writes: Vec<_> = references
        .iter()
        .filter(|reference| reference["type"] == json!("WRITE"))
        .filter(|reference| {
            text(reference, "/from")
                .and_then(address_offset)
                .is_ok_and(|from| (start..=end).contains(&from))
        })
        .collect();
    ensure!(
        !writes.is_empty(),
        "no WRITE reference from bump_counter: {result}"
    );

    let result = ctx.ok(
        "ghidra.reference",
        "list",
        json!({"filter": {"direction": "to", "to": counter, "type": "WRITE"}}),
    )?;
    ensure!(
        items(&result)?
            .iter()
            .all(|reference| reference["type"] == json!("WRITE")),
        "the type filter returned other references: {result}"
    );
    Ok(())
}

/// The first call in `main` references `bump_counter`.
fn list_from(ctx: &mut TestContext) -> Result<()> {
    let call = ctx.fact("call.main.first")?;
    let result = ctx.ok(
        "ghidra.reference",
        "list",
        json!({"filter": {"direction": "from", "from": call}}),
    )?;
    let references = items(&result)?;
    let target = ctx.entry("bump_counter")?;
    ensure!(
        references.iter().any(|reference| {
            reference["to"] == json!(target) && reference["type"] == json!("UNCONDITIONAL_CALL")
        }),
        "no call reference to bump_counter: {result}"
    );
    ctx.fail(
        "ghidra.reference",
        "list",
        json!({"filter": {"direction": "from"}}),
    )?;
    Ok(())
}
