//! `ghidra.decompilation` cases.

use anyhow::{ensure, Context, Result};
use serde_json::json;

use super::Case;
use crate::context::{offset_address, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("decompilation.text", decompile_text),
        Case::new("decompilation.tokens", decompile_tokens),
        Case::new("decompilation.errors", errors),
    ]
}

/// What the decompiled C code of one sample function must show.
pub struct Expectation {
    /// The function name in the signature line.
    pub function: &'static str,
    /// Names that the body must use, such as callees, parameters, and globals.
    pub identifiers: &'static [&'static str],
}

const EXPECTATIONS: [Expectation; 3] = [
    Expectation {
        function: "sum_points",
        identifiers: &["add_ints", "g_origin", "points", "count"],
    },
    Expectation {
        function: "bump_counter",
        identifiers: &["g_counter", "amount"],
    },
    Expectation {
        function: "color_name",
        identifiers: &["\"green\"", "\"unknown\""],
    },
];

/// Checks decompiled C code against an expectation.
///
/// Decompiler output changes between Ghidra versions: temporary names, casts, and blank
/// lines differ. The check therefore uses names that come from the sample source and its
/// DWARF data, not the exact text.
pub fn assert_decompiled_matches(c_code: &str, expected: &Expectation) -> Result<()> {
    let compact: String = c_code.split_whitespace().collect::<Vec<_>>().join(" ");
    let signature = compact.split('{').next().unwrap_or_default();
    ensure!(
        signature.contains(&format!("{}(", expected.function)),
        "the signature does not name {}: {signature}",
        expected.function
    );
    for identifier in expected.identifiers {
        ensure!(
            compact.contains(identifier),
            "the code of {} does not use {identifier}:\n{c_code}",
            expected.function
        );
    }
    Ok(())
}

fn decompile_text(ctx: &mut TestContext) -> Result<()> {
    for expected in &EXPECTATIONS {
        let entry = ctx.entry(expected.function)?;
        let result = ctx.ok(
            "ghidra.decompilation",
            "get",
            json!({"selector": {"entry": entry}, "format": "text", "scan": {"timeout_ms": 60000}}),
        )?;
        ensure!(
            result["completed"] == json!(true),
            "decompilation did not complete: {result}"
        );
        ensure!(result["entry"] == json!(entry), "wrong entry: {result}");
        ensure!(
            result["name"] == json!(expected.function),
            "wrong name: {result}"
        );
        assert_decompiled_matches(text(&result, "/c")?, expected)?;
    }
    Ok(())
}

fn decompile_tokens(ctx: &mut TestContext) -> Result<()> {
    let entry = ctx.entry("add_ints")?;
    let result = ctx.ok(
        "ghidra.decompilation",
        "get",
        json!({"selector": {"entry": entry}, "format": "tokens"}),
    )?;
    ensure!(
        result["format"] == json!("tokens"),
        "wrong format: {result}"
    );
    let tokens = result["tokens"].as_array().context("no tokens array")?;
    ensure!(!tokens.is_empty(), "no tokens: {result}");
    let joined: String = tokens
        .iter()
        .filter_map(|token| token.get("text").and_then(|text| text.as_str()))
        .collect();
    ensure!(
        joined.contains("add_ints"),
        "the tokens do not spell add_ints: {joined}"
    );
    Ok(())
}

fn errors(ctx: &mut TestContext) -> Result<()> {
    let inside = offset_address(&ctx.entry("main")?, 4)?;
    ctx.fail(
        "ghidra.decompilation",
        "get",
        json!({"selector": {"entry": inside}}),
    )?;
    let entry = ctx.entry("main")?;
    ctx.fail(
        "ghidra.decompilation",
        "get",
        json!({"selector": {"entry": entry}, "scan": {"timeout_ms": 50}}),
    )?;
    Ok(())
}
