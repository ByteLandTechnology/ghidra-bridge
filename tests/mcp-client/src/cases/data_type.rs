//! `ghidra.data_type` cases.

use anyhow::{ensure, Context, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{field_values, find_item, items, TestContext};

const CATEGORY: &str = "/mcp_client";

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("data_type.category_list", category_list),
        Case::new("data_type.list", list),
        Case::new("data_type.get", get),
        Case::new("data_type.struct_lifecycle", struct_lifecycle),
        Case::new("data_type.union_lifecycle", union_lifecycle),
        Case::new("data_type.enum_lifecycle", enum_lifecycle),
        Case::new("data_type.typedef_and_function", typedef_and_function),
    ]
}

fn named(name: &str) -> Value {
    json!({"kind": "named", "name": name})
}

fn path(name: &str) -> String {
    format!("{CATEGORY}/{name}")
}

fn get_type(ctx: &mut TestContext, path: &str) -> Result<Value> {
    ctx.ok(
        "ghidra.data_type",
        "get",
        json!({"selector": {"path": path}}),
    )
}

fn delete_type(ctx: &mut TestContext, path: &str) -> Result<()> {
    let result = ctx.ok(
        "ghidra.data_type",
        "delete",
        json!({"selector": {"path": path}}),
    )?;
    ensure!(
        result == json!({"deleted": true}),
        "delete {path} returned {result}"
    );
    ctx.fail(
        "ghidra.data_type",
        "get",
        json!({"selector": {"path": path}}),
    )?;
    Ok(())
}

fn category_list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.data_type",
        "category.list",
        json!({"page": {"limit": 1000}}),
    )?;
    let dwarf = find_item(items(&result)?, "path", "/DWARF")?;
    ensure!(
        dwarf["category_count"].as_i64().unwrap_or(0) > 0,
        "/DWARF has no subcategories"
    );

    let result = ctx.ok(
        "ghidra.data_type",
        "category.list",
        json!({"filter": {"path": "/DWARF"}, "page": {"limit": 1000}}),
    )?;
    find_item(items(&result)?, "path", "/DWARF/sample.h")?;
    Ok(())
}

fn list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.data_type",
        "list",
        json!({"filter": {"category_path": "/DWARF/sample.h"}, "page": {"limit": 1000}}),
    )?;
    let names = field_values(items(&result)?, "name");
    for name in ["Point", "Color", "binary_op"] {
        ensure!(
            names.contains(&name),
            "/DWARF/sample.h has no {name}: {names:?}"
        );
    }

    let result = ctx.ok(
        "ghidra.data_type",
        "list",
        json!({"filter": {"query": "Color", "kind": "enum"}, "page": {"limit": 1000}}),
    )?;
    let types = items(&result)?;
    ensure!(
        types.iter().all(|item| item["kind"] == json!("enum")),
        "the kind filter failed"
    );
    find_item(types, "path", "/DWARF/sample.h/Color")?;
    Ok(())
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let point = get_type(ctx, "/DWARF/sample.h/Point")?;
    ensure!(
        point["kind"] == json!("struct") && point["length"] == json!(8),
        "wrong Point: {point}"
    );
    let fields = point["fields"].as_array().context("Point has no fields")?;
    ensure!(
        field_values(fields, "name") == ["x", "y"],
        "wrong Point fields: {point}"
    );
    ensure!(
        fields[1]["offset"] == json!(4),
        "y is not at offset 4: {point}"
    );

    let color = get_type(ctx, "/DWARF/sample.h/Color")?;
    let values: Vec<(Value, Value)> = color["values"]
        .as_array()
        .context("Color has no values")?
        .iter()
        .map(|value| (value["name"].clone(), value["value"].clone()))
        .collect();
    ensure!(
        values
            == [
                (json!("COLOR_RED"), json!(1)),
                (json!("COLOR_GREEN"), json!(2)),
                (json!("COLOR_BLUE"), json!(4)),
            ],
        "wrong Color values: {color}"
    );

    ctx.fail(
        "ghidra.data_type",
        "get",
        json!({"selector": {"path": "/missing/Type"}}),
    )?;
    Ok(())
}

fn struct_lifecycle(ctx: &mut TestContext) -> Result<()> {
    let pair = path("McpPair");
    let result = ctx.ok(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "struct", "name": "McpPair", "category_path": CATEGORY}}),
    )?;
    ensure!(
        result["path"] == json!(pair) && result["kind"] == json!("struct"),
        "create: {result}"
    );
    ctx.fail_with(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "struct", "name": "McpPair", "category_path": CATEGORY}}),
        409,
        "data_type_exists",
    )?;

    let result = ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": pair}, "patch": {"kind": "struct", "add_fields": [
            {"name": "left", "data_type": named("int")},
            {"name": "right", "data_type": named("int")},
        ]}}),
    )?;
    ensure!(
        result["length"] == json!(8),
        "the struct is not 8 bytes: {result}"
    );
    let fields = result["fields"].as_array().context("no fields")?;
    ensure!(
        field_values(fields, "name") == ["left", "right"],
        "add_fields: {result}"
    );

    let result = ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": pair}, "patch": {"kind": "struct",
            "rename_fields": [{"name": "left", "new_name": "first"}],
            "update_fields": [{"name": "right", "data_type": named("uint")}],
        }}),
    )?;
    let fields = result["fields"].as_array().context("no fields")?;
    ensure!(
        field_values(fields, "name") == ["first", "right"],
        "rename_fields: {result}"
    );
    ensure!(
        fields[1]["data_type"] == named("/uint"),
        "update_fields: {result}"
    );

    let result = ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": pair}, "patch": {"kind": "struct", "remove_fields": [{"name": "first"}]}}),
    )?;
    let fields = result["fields"].as_array().context("no fields")?;
    ensure!(
        field_values(fields, "name") == ["right"],
        "remove_fields: {result}"
    );

    delete_type(ctx, &pair)
}

fn union_lifecycle(ctx: &mut TestContext) -> Result<()> {
    let value = path("McpValue");
    ctx.ok(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "union", "name": "McpValue", "category_path": CATEGORY}}),
    )?;
    let result = ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": value}, "patch": {"kind": "union", "add_fields": [
            {"name": "as_int", "data_type": named("int")},
            {"name": "as_double", "data_type": named("double")},
        ]}}),
    )?;
    ensure!(
        result["kind"] == json!("union") && result["length"] == json!(8),
        "union: {result}"
    );
    delete_type(ctx, &value)
}

fn enum_lifecycle(ctx: &mut TestContext) -> Result<()> {
    let mode = path("McpMode");
    let result = ctx.ok(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "enum", "name": "McpMode", "category_path": CATEGORY, "size": 2}}),
    )?;
    ensure!(
        result["size"] == json!(2),
        "the enum is not 2 bytes: {result}"
    );

    ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": mode}, "patch": {"kind": "enum", "add_values": [
            {"name": "MODE_READ", "value": 1},
            {"name": "MODE_WRITE", "value": 2},
        ]}}),
    )?;
    let result = ctx.ok(
        "ghidra.data_type",
        "patch",
        json!({"selector": {"path": mode}, "patch": {"kind": "enum",
            "rename_values": [{"name": "MODE_READ", "new_name": "MODE_INPUT"}],
            "remove_values": [{"name": "MODE_WRITE"}],
        }}),
    )?;
    let values = result["values"].as_array().context("no values")?;
    ensure!(
        field_values(values, "name") == ["MODE_INPUT"],
        "enum patch: {result}"
    );
    delete_type(ctx, &mode)
}

fn typedef_and_function(ctx: &mut TestContext) -> Result<()> {
    let alias = path("McpInt");
    let result = ctx.ok(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "typedef", "name": "McpInt", "category_path": CATEGORY, "base_type": named("int")}}),
    )?;
    ensure!(
        result["base_type"] == named("/int"),
        "wrong typedef base: {result}"
    );

    let callback = path("McpCallback");
    let signature = |return_type: &str| {
        json!({
            "return_type": named(return_type),
            "parameters": [{"name": "value", "data_type": named("McpInt")}],
            "calling_convention": "__stdcall",
            "has_var_args": false,
            "has_no_return": false,
        })
    };
    let result = ctx.ok(
        "ghidra.data_type",
        "create",
        json!({"resource": {"kind": "function", "name": "McpCallback", "category_path": CATEGORY, "signature": signature("int")}}),
    )?;
    ensure!(
        result["kind"] == json!("function"),
        "wrong function type: {result}"
    );
    ensure!(
        result["signature"]["parameters"][0]["data_type"] == named(&alias),
        "the parameter does not use the typedef: {result}"
    );

    // upsert replaces the signature of the existing definition.
    let result = ctx.ok(
        "ghidra.data_type",
        "upsert",
        json!({"resource": {"kind": "function", "name": "McpCallback", "category_path": CATEGORY, "signature": signature("long")}}),
    )?;
    ensure!(
        result["signature"]["return_type"] == named("/long"),
        "upsert: {result}"
    );
    ensure!(
        get_type(ctx, &callback)?["signature"] == result["signature"],
        "upsert did not persist"
    );

    delete_type(ctx, &callback)?;
    delete_type(ctx, &alias)
}
