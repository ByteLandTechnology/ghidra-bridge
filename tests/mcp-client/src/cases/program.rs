//! `ghidra.program` cases.

use anyhow::{ensure, Result};
use serde_json::json;

use super::bridge::binary_name;
use super::Case;
use crate::context::{integer, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("program.get", get),
        Case::new("program.language_get", language_get),
    ]
}

pub fn save_cases() -> Vec<Case> {
    vec![Case::new("program.save", save)]
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok("ghidra.program", "get", json!({}))?;
    ensure!(
        result["name"] == json!(binary_name(ctx)),
        "wrong program name: {result}"
    );
    let path = ctx.binary.to_string_lossy().into_owned();
    ensure!(
        result["executable_path"] == json!(path),
        "wrong executable_path: {result}"
    );
    ensure!(
        text(&result, "/language_id")?.starts_with("x86:LE:64:"),
        "not x86-64: {result}"
    );
    ensure!(
        result["compiler_spec_id"] == json!("gcc"),
        "not gcc: {result}"
    );
    ensure!(
        text(&result, "/executable_format")?.contains("ELF"),
        "not an ELF program: {result}"
    );
    ensure!(
        integer(&result, "/function_count")? >= 9,
        "too few functions: {result}"
    );
    ensure!(
        integer(&result, "/symbol_count")? > 0,
        "no symbols: {result}"
    );
    ensure!(
        result["image_base"] == result["min_address"],
        "image_base is not min_address"
    );

    let result = ctx.ok(
        "ghidra.program",
        "get",
        json!({"projection": {"fields": ["function_count"]}}),
    )?;
    ensure!(
        result.get("function_count").is_some(),
        "projection lost the field: {result}"
    );
    ensure!(
        result.get("executable_path").is_none(),
        "projection kept other fields: {result}"
    );
    Ok(())
}

fn language_get(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok("ghidra.program", "language.get", json!({}))?;
    ensure!(
        result["processor"] == json!("x86"),
        "wrong processor: {result}"
    );
    ensure!(
        result["endian"] == json!("little"),
        "wrong endian: {result}"
    );
    ensure!(
        result["address_size"] == json!(64),
        "wrong address size: {result}"
    );
    ensure!(
        result["compiler_spec_id"] == json!("gcc"),
        "wrong compiler spec: {result}"
    );
    Ok(())
}

fn save(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok("ghidra.program", "save", json!({}))?;
    ensure!(
        result == json!({"saved": true}),
        "unexpected save result: {result}"
    );
    Ok(())
}
