//! `ghidra.function` cases.

use std::collections::BTreeSet;

use anyhow::{ensure, Result};
use serde_json::{json, Value};

use super::Case;
use crate::context::{field_values, find_item, items, offset_address, TestContext};

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("function.list", list),
        Case::new("function.get", get),
        Case::new("function.patch", patch),
        Case::new("function.parameters", parameters),
        Case::new("function.local_variable_patch", local_variable_patch),
        Case::new("function.call_list", call_list),
    ]
}

fn named(name: &str) -> Value {
    json!({"kind": "named", "name": name})
}

fn get_function(ctx: &mut TestContext, entry: &str) -> Result<Value> {
    ctx.ok(
        "ghidra.function",
        "get",
        json!({"selector": {"entry": entry}}),
    )
}

fn list(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.ok(
        "ghidra.function",
        "list",
        json!({"filter": {"name": "sum_points"}}),
    )?;
    let function = find_item(items(&result)?, "name", "sum_points")?;
    ensure!(
        function["parameter_count"] == json!(2),
        "sum_points has 2 parameters: {function}"
    );
    let names = field_values(
        function["parameters"].as_array().map_or(&[], Vec::as_slice),
        "name",
    );
    ensure!(
        names == ["points", "count"],
        "wrong parameter names: {names:?}"
    );
    ensure!(
        function["return_type"] == named("/int"),
        "sum_points returns int: {function}"
    );

    // The entry filter selects one function.
    let entry = ctx.entry("add_ints")?;
    let result = ctx.ok(
        "ghidra.function",
        "list",
        json!({"filter": {"entry": entry}}),
    )?;
    ensure!(
        field_values(items(&result)?, "name") == ["add_ints"],
        "entry filter failed: {result}"
    );

    // The contains filter selects the functions whose body holds an address.
    let inside = offset_address(&ctx.entry("main")?, 4)?;
    let result = ctx.ok(
        "ghidra.function",
        "list",
        json!({"filter": {"contains": inside}}),
    )?;
    ensure!(
        field_values(items(&result)?, "name") == ["main"],
        "contains filter failed: {result}"
    );

    let result = ctx.ok(
        "ghidra.function",
        "list",
        json!({"filter": {"thunk": false, "external": false}, "page": {"limit": 1000}}),
    )?;
    let names: BTreeSet<&str> = field_values(items(&result)?, "name").into_iter().collect();
    for name in super::setup::SAMPLE_FUNCTIONS {
        ensure!(
            names.contains(name),
            "{name} is missing from the function list"
        );
    }
    Ok(())
}

fn get(ctx: &mut TestContext) -> Result<()> {
    let main = ctx.entry("main")?;
    let result = get_function(ctx, &main)?;
    ensure!(result["name"] == json!("main"), "wrong name: {result}");
    ensure!(result["entry"] == json!(main), "wrong entry: {result}");
    ensure!(
        result["namespace"] == json!("Global"),
        "wrong namespace: {result}"
    );
    let parameters = result["parameters"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    ensure!(
        field_values(parameters, "name") == ["argc", "argv"],
        "wrong parameters: {result}"
    );
    let locals = result["local_variables"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    let local_names = field_values(locals, "name");
    for local in ["sum", "product", "check", "area", "points"] {
        ensure!(
            local_names.contains(&local),
            "main has no local {local}: {local_names:?}"
        );
    }

    let result = ctx.ok(
        "ghidra.function",
        "get",
        json!({"selector": {"entry": main}, "projection": {"fields": ["signature"]}}),
    )?;
    ensure!(
        result.get("local_variables").is_none(),
        "projection kept locals: {result}"
    );
    ensure!(
        result["signature"]
            .as_str()
            .is_some_and(|signature| signature.contains("main")),
        "no signature: {result}"
    );

    // The selector must be an entry point, not an address inside the body.
    ctx.fail_with(
        "ghidra.function",
        "get",
        json!({"selector": {"entry": offset_address(&main, 4)?}}),
        404,
        "resource_not_found",
    )?;
    Ok(())
}

fn patch(ctx: &mut TestContext) -> Result<()> {
    let entry = ctx.entry("add_ints")?;
    let selector = json!({"entry": entry});

    let result = ctx.ok(
        "ghidra.function",
        "patch",
        json!({"selector": selector, "patch": {"name": "add_values", "comment": "Adds two ints."}}),
    )?;
    ensure!(
        result["name"] == json!("add_values"),
        "rename failed: {result}"
    );
    ensure!(
        result["comment"] == json!("Adds two ints."),
        "comment failed: {result}"
    );
    ensure!(
        get_function(ctx, &entry)?["name"] == json!("add_values"),
        "rename did not persist"
    );

    let result = ctx.ok(
        "ghidra.function",
        "patch",
        json!({"selector": selector, "patch": {"name": "add_ints", "comment": null}}),
    )?;
    ensure!(
        result["name"] == json!("add_ints"),
        "restore failed: {result}"
    );
    ensure!(
        result.get("comment").is_none(),
        "a null comment must clear it: {result}"
    );

    ctx.fail(
        "ghidra.function",
        "patch",
        json!({"selector": selector, "patch": {}}),
    )?;
    Ok(())
}

fn parameters(ctx: &mut TestContext) -> Result<()> {
    let entry = ctx.entry("add_ints")?;
    let result = ctx.ok(
        "ghidra.function",
        "parameter.create",
        json!({
            "selector": {"entry": entry},
            "resource": {"ordinal": 2, "name": "extra", "data_type": named("int")},
        }),
    )?;
    ensure!(
        result["name"] == json!("extra") && result["ordinal"] == json!(2),
        "create: {result}"
    );
    ensure!(
        get_function(ctx, &entry)?["parameter_count"] == json!(3),
        "parameter not added"
    );

    let result = ctx.ok(
        "ghidra.function",
        "parameter.patch",
        json!({
            "selector": {"entry": entry, "ordinal": 2},
            "patch": {"name": "extra_long", "data_type": named("long")},
        }),
    )?;
    ensure!(
        result["name"] == json!("extra_long"),
        "rename failed: {result}"
    );
    ensure!(
        result["data_type"] == named("/long"),
        "retype failed: {result}"
    );

    let result = ctx.ok(
        "ghidra.function",
        "parameter.delete",
        json!({"selector": {"entry": entry, "ordinal": 2}}),
    )?;
    ensure!(
        result == json!({"deleted": true}),
        "unexpected delete result: {result}"
    );
    let function = get_function(ctx, &entry)?;
    ensure!(
        function["parameter_count"] == json!(2),
        "parameter not deleted: {function}"
    );

    ctx.fail(
        "ghidra.function",
        "parameter.delete",
        json!({"selector": {"entry": entry, "ordinal": 9}}),
    )?;
    Ok(())
}

fn local_variable_patch(ctx: &mut TestContext) -> Result<()> {
    let main = ctx.entry("main")?;
    let result = ctx.ok(
        "ghidra.function",
        "local_variable.patch",
        json!({"selector": {"entry": main, "name": "sum"}, "patch": {"name": "point_sum"}}),
    )?;
    ensure!(
        result["name"] == json!("point_sum"),
        "rename failed: {result}"
    );
    let function = get_function(ctx, &main)?;
    let locals = function["local_variables"]
        .as_array()
        .map_or(&[][..], Vec::as_slice);
    ensure!(
        field_values(locals, "name").contains(&"point_sum"),
        "rename did not persist"
    );

    ctx.ok(
        "ghidra.function",
        "local_variable.patch",
        json!({"selector": {"entry": main, "name": "point_sum"}, "patch": {"name": "sum"}}),
    )?;
    ctx.fail(
        "ghidra.function",
        "local_variable.patch",
        json!({"selector": {"entry": main, "name": "missing_local"}, "patch": {"name": "x"}}),
    )?;
    Ok(())
}

fn call_names(
    ctx: &mut TestContext,
    function: &str,
    direction: Option<&str>,
) -> Result<BTreeSet<String>> {
    let mut filter = json!({"entry": ctx.entry(function)?});
    if let Some(direction) = direction {
        filter["direction"] = json!(direction);
    }
    let result = ctx.ok("ghidra.function", "call.list", json!({"filter": filter}))?;
    let calls = items(&result)?;
    let expected = direction.unwrap_or("callees");
    ensure!(
        calls
            .iter()
            .all(|call| call["direction"] == json!(expected)),
        "{function} {expected} have the wrong direction: {result}"
    );
    Ok(field_values(calls, "name")
        .into_iter()
        .map(str::to_string)
        .collect())
}

fn call_list(ctx: &mut TestContext) -> Result<()> {
    // The default direction is callees.
    let callees = call_names(ctx, "main", None)?;
    for name in [
        "bump_counter",
        "sum_points",
        "apply_op",
        "checksum_bytes",
        "cpp_total_area",
        "color_name",
    ] {
        ensure!(
            callees.contains(name),
            "main does not call {name}: {callees:?}"
        );
    }
    ensure!(
        !callees.contains("add_ints"),
        "main does not call add_ints directly"
    );

    let callees = call_names(ctx, "sum_points", Some("callees"))?;
    ensure!(
        callees.contains("add_ints"),
        "sum_points does not call add_ints: {callees:?}"
    );

    let callers = call_names(ctx, "add_ints", Some("callers"))?;
    let expected: BTreeSet<String> = ["cpp_total_area", "sum_points"].map(String::from).into();
    ensure!(callers == expected, "add_ints callers are {callers:?}");

    let callers = call_names(ctx, "bump_counter", Some("callers"))?;
    ensure!(
        callers.contains("main") && callers.contains("cpp_total_area"),
        "bump_counter callers: {callers:?}"
    );
    Ok(())
}
