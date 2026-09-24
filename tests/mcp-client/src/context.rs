use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

use crate::mcp::McpClient;
use crate::schema::SchemaCache;

/// Shared state for the test cases.
pub struct TestContext<'a> {
    pub client: &'a McpClient,
    /// Canonical path of the binary that Ghidra imported.
    pub binary: PathBuf,
    /// Every `tool/operation` pair that `tools/list` publishes.
    pub published: BTreeSet<String>,
    /// Every `tool/operation` pair that returned a valid successful result.
    pub covered: BTreeSet<String>,
    schemas: SchemaCache,
    facts: BTreeMap<String, String>,
}

impl<'a> TestContext<'a> {
    pub fn new(client: &'a McpClient, binary: PathBuf) -> Self {
        Self {
            client,
            binary,
            published: BTreeSet::new(),
            covered: BTreeSet::new(),
            schemas: SchemaCache::default(),
            facts: BTreeMap::new(),
        }
    }

    /// Calls an operation that must succeed and returns its `result`.
    ///
    /// The request must match the operation's inputSchema and the result must match its
    /// outputSchema.
    pub fn ok(&mut self, tool: &str, operation: &str, params: Value) -> Result<Value> {
        self.schemas
            .check_input(self.client, tool, operation, &params)?;
        let reply = self.client.call_tool(
            tool,
            json!({"operation": operation, "params": params.clone()}),
        )?;
        if reply.is_error {
            bail!(
                "{tool} {operation} failed: {}\nparams: {params}",
                reply.structured
            );
        }
        ensure!(
            reply.structured.get("operation") == Some(&json!(operation)),
            "{tool} {operation} returned the wrong operation: {}",
            reply.structured
        );
        let result = reply
            .structured
            .get("result")
            .cloned()
            .with_context(|| format!("{tool} {operation} returned no result"))?;
        self.schemas
            .check_output(self.client, tool, operation, &result)?;
        self.covered.insert(format!("{tool}/{operation}"));
        Ok(result)
    }

    /// Calls an operation that must fail and returns the bridge error.
    pub fn fail(&mut self, tool: &str, operation: &str, params: Value) -> Result<Value> {
        self.fail_arguments(tool, json!({"operation": operation, "params": params}))
    }

    /// Calls an operation that must fail with the given HTTP status and error code.
    pub fn fail_with(
        &mut self,
        tool: &str,
        operation: &str,
        params: Value,
        status: u16,
        code: &str,
    ) -> Result<Value> {
        let error = self.fail(tool, operation, params)?;
        expect_error(&error, status, code)?;
        Ok(error)
    }

    /// Calls a tool with raw arguments that must produce a tool error.
    pub fn fail_arguments(&mut self, tool: &str, arguments: Value) -> Result<Value> {
        let reply = self.client.call_tool(tool, arguments.clone())?;
        ensure!(
            reply.is_error,
            "{tool} succeeded but an error was expected: {}\narguments: {arguments}",
            reply.structured
        );
        let error = reply.structured;
        let status = error.get("status").and_then(Value::as_u64).unwrap_or(0);
        ensure!(
            (400..=599).contains(&status),
            "error has no valid status: {error}"
        );
        ensure!(
            error
                .get("code")
                .and_then(Value::as_str)
                .is_some_and(|code| !code.is_empty()),
            "error has no code: {error}"
        );
        ensure!(
            error
                .get("message")
                .and_then(Value::as_str)
                .is_some_and(|text| !text.is_empty()),
            "error has no message: {error}"
        );
        Ok(error)
    }

    pub fn mark_covered(&mut self, key: &str) {
        self.covered.insert(key.to_string());
    }

    pub fn set_fact(&mut self, key: &str, value: impl Into<String>) {
        self.facts.insert(key.to_string(), value.into());
    }

    pub fn fact(&self, key: &str) -> Result<String> {
        self.facts
            .get(key)
            .cloned()
            .with_context(|| format!("fact {key} is not known; did the setup cases run?"))
    }

    /// Entry address of a function in the sample binary.
    pub fn entry(&self, function: &str) -> Result<String> {
        self.fact(&format!("entry.{function}"))
    }
}

/// Checks the status and code of a bridge error.
pub fn expect_error(error: &Value, status: u16, code: &str) -> Result<()> {
    ensure!(
        error.get("status") == Some(&json!(status)) && error.get("code") == Some(&json!(code)),
        "expected error {status} {code}, got {error}"
    );
    Ok(())
}

/// Returns the `items` array of a list result.
pub fn items(result: &Value) -> Result<&Vec<Value>> {
    result
        .get("items")
        .and_then(Value::as_array)
        .with_context(|| format!("result has no items array: {result}"))
}

/// Returns the string at a JSON pointer.
pub fn text<'v>(value: &'v Value, pointer: &str) -> Result<&'v str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .with_context(|| format!("no string at {pointer} in {value}"))
}

/// Returns the integer at a JSON pointer.
pub fn integer(value: &Value, pointer: &str) -> Result<i64> {
    value
        .pointer(pointer)
        .and_then(Value::as_i64)
        .with_context(|| format!("no integer at {pointer} in {value}"))
}

/// Returns the string field `field` of every item.
pub fn field_values<'v>(items: &'v [Value], field: &str) -> Vec<&'v str> {
    items
        .iter()
        .filter_map(|item| item.get(field).and_then(Value::as_str))
        .collect()
}

/// Finds the item whose `field` equals `expected`.
pub fn find_item<'v>(items: &'v [Value], field: &str, expected: &str) -> Result<&'v Value> {
    items
        .iter()
        .find(|item| item.get(field).and_then(Value::as_str) == Some(expected))
        .with_context(|| {
            format!(
                "no item with {field}={expected} in {}",
                Value::from(items.to_vec())
            )
        })
}

/// Splits an address such as `ram:00101199` into its space and offset.
pub fn parse_address(address: &str) -> Result<(&str, u64)> {
    let (space, offset) = address
        .rsplit_once(':')
        .with_context(|| format!("address {address} has no space prefix"))?;
    let offset = u64::from_str_radix(offset, 16)
        .with_context(|| format!("address {address} has no hex offset"))?;
    Ok((space, offset))
}

/// Returns the address `delta` bytes after `address`, in the same format.
pub fn offset_address(address: &str, delta: u64) -> Result<String> {
    let (space, offset) = parse_address(address)?;
    let digits = address.len() - space.len() - 1;
    Ok(format!("{space}:{:0digits$x}", offset + delta))
}

/// Compares two addresses in the same space.
pub fn address_offset(address: &str) -> Result<u64> {
    parse_address(address).map(|(_, offset)| offset)
}
