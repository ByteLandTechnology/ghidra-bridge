use std::collections::HashMap;

use anyhow::{anyhow, bail, Context, Result};
use jsonschema::Validator;
use serde_json::{json, Value};

use crate::mcp::McpClient;

/// Input and output validators for one tool operation.
struct OperationSchemas {
    input: Validator,
    output: Validator,
}

/// Caches the per-operation schemas that `ghidra.help` returns.
///
/// The schemas in `tools/list` keep `$defs` inside each operation's `params`, while their
/// `$ref` values point at the document root. `ghidra.help` returns each schema as a
/// standalone document, so the references resolve.
#[derive(Default)]
pub struct SchemaCache {
    operations: HashMap<(String, String), OperationSchemas>,
}

impl SchemaCache {
    pub fn check_input(
        &mut self,
        client: &McpClient,
        tool: &str,
        operation: &str,
        params: &Value,
    ) -> Result<()> {
        let schemas = self.load(client, tool, operation)?;
        check(&schemas.input, params).with_context(|| {
            format!("the test request for {tool} {operation} does not match inputSchema")
        })
    }

    pub fn check_output(
        &mut self,
        client: &McpClient,
        tool: &str,
        operation: &str,
        result: &Value,
    ) -> Result<()> {
        let schemas = self.load(client, tool, operation)?;
        check(&schemas.output, result)
            .with_context(|| format!("the {tool} {operation} result does not match outputSchema"))
    }

    fn load(
        &mut self,
        client: &McpClient,
        tool: &str,
        operation: &str,
    ) -> Result<&OperationSchemas> {
        let key = (tool.to_string(), operation.to_string());
        if !self.operations.contains_key(&key) {
            let reply = client.call_tool(
                "ghidra.help",
                json!({"domain": tool, "operation": operation}),
            )?;
            if reply.is_error {
                bail!(
                    "ghidra.help failed for {tool} {operation}: {}",
                    reply.structured
                );
            }
            let help = reply.structured;
            let input = compile(&help, "inputSchema")?;
            let output = compile(&help, "outputSchema")?;
            self.operations
                .insert(key.clone(), OperationSchemas { input, output });
        }
        Ok(&self.operations[&key])
    }
}

fn compile(help: &Value, field: &str) -> Result<Validator> {
    let schema = help
        .get(field)
        .with_context(|| format!("ghidra.help has no {field}: {help}"))?;
    jsonschema::validator_for(schema).map_err(|error| anyhow!("invalid {field}: {error}"))
}

fn check(validator: &Validator, instance: &Value) -> Result<()> {
    let errors: Vec<String> = validator
        .iter_errors(instance)
        .take(5)
        .map(|error| format!("{} at {}", error, error.instance_path()))
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        bail!("{}\ninstance: {instance}", errors.join("\n"))
    }
}
