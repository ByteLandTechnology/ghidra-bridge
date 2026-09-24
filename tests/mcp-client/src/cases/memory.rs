//! `ghidra.memory` cases.

use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde_json::json;

use super::Case;
use crate::context::{find_item, items, text, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("memory.block_list", block_list),
        Case::new("memory.block_get", block_get),
        Case::new("memory.read", read),
        Case::new("memory.write", write),
    ]
}

fn block_list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.memory",
        "block.list",
        json!({"page": {"limit": 1000}}),
    )?;
    let blocks = items(&result)?;
    let text_block = find_item(blocks, "name", ".text")?;
    ensure!(
        text_block["execute"] == json!(true) && text_block["write"] == json!(false),
        ".text must be executable and read-only: {text_block}"
    );
    let data = find_item(blocks, "name", ".data")?;
    ensure!(
        data["write"] == json!(true),
        ".data must be writable: {data}"
    );
    let bss = find_item(blocks, "name", ".bss")?;
    ensure!(
        bss["initialized"] == json!(false),
        ".bss must be uninitialized: {bss}"
    );

    let result = ctx.ok(
        "ghidra.memory",
        "block.list",
        json!({"filter": {"execute": true}, "page": {"limit": 1000}}),
    )?;
    let executable = items(&result)?;
    ensure!(
        executable
            .iter()
            .all(|block| block["execute"] == json!(true)),
        "the execute filter returned other blocks"
    );
    find_item(executable, "name", ".text")?;

    let result = ctx.ok(
        "ghidra.memory",
        "block.list",
        json!({"filter": {"name": ".data"}}),
    )?;
    find_item(items(&result)?, "name", ".data")?;
    Ok(())
}

fn block_get(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.memory",
        "block.get",
        json!({"selector": {"name": ".text"}}),
    )?;
    ensure!(result["name"] == json!(".text"), "wrong block: {result}");
    ensure!(
        result["start"] == json!(ctx.fact("block.text.start")?),
        "wrong start: {result}"
    );
    ensure!(
        result["end"] == json!(ctx.fact("block.text.end")?),
        "wrong end: {result}"
    );
    ctx.fail(
        "ghidra.memory",
        "block.get",
        json!({"selector": {"name": ".missing"}}),
    )?;
    Ok(())
}

/// Ghidra maps the ELF header at the image base, so memory there equals the file start.
fn read(ctx: &mut TestContext) -> Result<()> {
    let file = std::fs::read(&ctx.binary)?;
    let base = ctx.fact("image_base")?;
    let hex = read_bytes(ctx, &base, 64, "hex")?;
    let base64 = read_bytes(ctx, &base, 64, "base64")?;
    ensure!(hex == base64, "hex and base64 reads differ");
    ensure!(
        hex == file[..64],
        "memory at the image base differs from the file header"
    );

    // The default encoding is hex and the default length is 256.
    let result = ctx.ok(
        "ghidra.memory",
        "read",
        json!({"selector": {"address": base}}),
    )?;
    ensure!(
        result["bytes"]["encoding"] == json!("hex"),
        "default encoding is not hex"
    );
    ensure!(
        result["bytes"]["length"] == json!(256),
        "default length is not 256"
    );

    let banner = ctx.fact("global.g_banner")?;
    let bytes = read_bytes(ctx, &banner, 21, "hex")?;
    ensure!(
        bytes == b"ghidra-bridge-sample\0",
        "g_banner bytes are wrong: {bytes:?}"
    );

    ctx.fail(
        "ghidra.memory",
        "read",
        json!({"selector": {"address": base}, "length": 0}),
    )?;
    Ok(())
}

fn write(ctx: &mut TestContext) -> Result<()> {
    let table = ctx.fact("global.g_lookup_table")?;
    let original = read_bytes(ctx, &table, 4, "hex")?;
    ensure!(
        original == [0x10, 0x21, 0x32, 0x43],
        "unexpected g_lookup_table bytes"
    );

    let result = ctx.ok(
        "ghidra.memory",
        "write",
        json!({
            "selector": {"address": table},
            "patch": {"bytes": {"encoding": "hex", "data": "deadbeef", "length": 4}},
        }),
    )?;
    ensure!(
        result == json!({"start": table, "length": 4}),
        "unexpected write result: {result}"
    );
    ensure!(
        read_bytes(ctx, &table, 4, "hex")? == [0xde, 0xad, 0xbe, 0xef],
        "write did not persist"
    );

    // Restore the original bytes with base64.
    let encoded = base64::engine::general_purpose::STANDARD.encode(&original);
    ctx.ok(
        "ghidra.memory",
        "write",
        json!({
            "selector": {"address": table},
            "patch": {"bytes": {"encoding": "base64", "data": encoded, "length": 4}},
        }),
    )?;
    ensure!(
        read_bytes(ctx, &table, 4, "hex")? == original,
        "restore did not persist"
    );

    // The declared length must match the data.
    ctx.fail(
        "ghidra.memory",
        "write",
        json!({
            "selector": {"address": table},
            "patch": {"bytes": {"encoding": "hex", "data": "dead", "length": 4}},
        }),
    )?;
    Ok(())
}

fn read_bytes(
    ctx: &mut TestContext,
    address: &str,
    length: usize,
    encoding: &str,
) -> Result<Vec<u8>> {
    let result = ctx.ok(
        "ghidra.memory",
        "read",
        json!({"selector": {"address": address}, "length": length, "encoding": encoding}),
    )?;
    ensure!(
        result["address"] == json!(address),
        "wrong address: {result}"
    );
    ensure!(
        result["bytes"]["encoding"] == json!(encoding),
        "wrong encoding: {result}"
    );
    ensure!(
        result["bytes"]["length"] == json!(length),
        "wrong length: {result}"
    );
    let data = text(&result, "/bytes/data")?;
    decode(encoding, data).with_context(|| format!("cannot decode {result}"))
}

pub fn decode(encoding: &str, data: &str) -> Result<Vec<u8>> {
    match encoding {
        "base64" => Ok(base64::engine::general_purpose::STANDARD.decode(data)?),
        _ => (0..data.len())
            .step_by(2)
            .map(|index| Ok(u8::from_str_radix(&data[index..index + 2], 16)?))
            .collect(),
    }
}
