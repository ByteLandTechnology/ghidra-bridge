use std::cell::Cell;
use std::time::Duration;

use anyhow::{bail, ensure, Context, Result};
use serde_json::{json, Value};

pub const PROTOCOL_VERSION: &str = "2026-07-28";

/// The tool prefix that the test cases use. The client replaces it with the prefix of the
/// server under test.
pub const DEFAULT_TOOL_PREFIX: &str = "ghidra";

/// A raw HTTP response from the MCP endpoint.
#[derive(Debug)]
pub struct HttpReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl HttpReply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> Result<Value> {
        serde_json::from_str(&self.body)
            .with_context(|| format!("HTTP {} body is not JSON: {}", self.status, self.body))
    }

    /// Returns the JSON-RPC error code of the reply.
    pub fn rpc_error_code(&self) -> Result<i64> {
        let body = self.json()?;
        body.pointer("/error/code")
            .and_then(Value::as_i64)
            .with_context(|| format!("reply has no JSON-RPC error code: {body}"))
    }
}

/// The parsed result of a `tools/call` request.
#[derive(Debug)]
pub struct ToolReply {
    pub is_error: bool,
    pub structured: Value,
}

/// MCP Streamable HTTP client for the Ghidra Bridge server.
///
/// Every request carries the metadata and headers that the server requires.
///
/// Test cases name tools with the default prefix, such as `ghidra.program`. The client
/// sends them with the prefix of the server, such as `re1.program`.
pub struct McpClient {
    endpoint: String,
    token: Option<String>,
    tool_prefix: String,
    agent: ureq::Agent,
    next_id: Cell<u64>,
}

impl McpClient {
    pub fn new(endpoint: String, token: Option<String>, tool_prefix: String) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(600)))
            .build()
            .into();
        Self {
            endpoint,
            token,
            tool_prefix,
            agent,
            next_id: Cell::new(1),
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn tool_prefix(&self) -> &str {
        &self.tool_prefix
    }

    /// Converts a tool name with the default prefix to the name that the server uses.
    pub fn wire_name(&self, name: &str) -> String {
        match name
            .strip_prefix(DEFAULT_TOOL_PREFIX)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            Some(domain) => format!("{}.{domain}", self.tool_prefix),
            None => name.to_string(),
        }
    }

    /// Converts a tool name that the server uses to the name with the default prefix.
    pub fn logical_name(&self, name: &str) -> String {
        match name
            .strip_prefix(&self.tool_prefix)
            .and_then(|rest| rest.strip_prefix('.'))
        {
            Some(domain) => format!("{DEFAULT_TOOL_PREFIX}.{domain}"),
            None => name.to_string(),
        }
    }

    /// Sends an HTTP request exactly as given. `url_suffix` is appended to the endpoint.
    pub fn send(
        &self,
        http_method: &str,
        url_suffix: &str,
        headers: &[(String, String)],
        body: Option<&str>,
    ) -> Result<HttpReply> {
        let mut builder = ureq::http::Request::builder()
            .method(http_method)
            .uri(format!("{}{url_suffix}", self.endpoint));
        for (name, value) in headers {
            builder = builder.header(name, value);
        }
        let request = builder.body(body.unwrap_or_default().as_bytes().to_vec())?;
        let mut response = self
            .agent
            .run(request)
            .with_context(|| format!("{http_method} {} failed", self.endpoint))?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = response.body_mut().read_to_string().unwrap_or_default();
        Ok(HttpReply {
            status,
            headers,
            body,
        })
    }

    /// Builds a JSON-RPC request envelope with MCP metadata in `params._meta`.
    ///
    /// For `tools/call`, the tool name and the `ghidra.help` domain get the server prefix.
    pub fn envelope(&self, method: &str, mut params: Value) -> Value {
        if method == "tools/call" {
            let name = params
                .get("name")
                .and_then(Value::as_str)
                .map(|name| self.wire_name(name));
            if let Some(name) = name {
                if name == self.wire_name("ghidra.help") {
                    if let Some(domain) =
                        params.pointer("/arguments/domain").and_then(Value::as_str)
                    {
                        params["arguments"]["domain"] = json!(self.wire_name(domain));
                    }
                }
                params["name"] = json!(name);
            }
        }
        self.envelope_exact(method, params)
    }

    /// Builds a request envelope without changing tool names.
    pub fn envelope_exact(&self, method: &str, params: Value) -> Value {
        let mut params = match params {
            Value::Object(map) => map,
            Value::Null => serde_json::Map::new(),
            other => panic!("params must be an object, got {other}"),
        };
        params.insert("_meta".into(), meta());
        json!({"jsonrpc": "2.0", "id": self.take_id(), "method": method, "params": params})
    }

    /// Returns the headers that the server requires for `method`.
    pub fn headers_for(&self, method: &str, name: Option<&str>) -> Vec<(String, String)> {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            (
                "MCP-Protocol-Version".to_string(),
                PROTOCOL_VERSION.to_string(),
            ),
            ("Mcp-Method".to_string(), method.to_string()),
        ];
        if let Some(name) = name {
            headers.push(("Mcp-Name".to_string(), name.to_string()));
        }
        if let Some(token) = &self.token {
            headers.push(("Authorization".to_string(), format!("Bearer {token}")));
        }
        headers
    }

    /// Sends a well-formed MCP request and returns the raw reply.
    pub fn rpc_raw(&self, method: &str, params: Value) -> Result<HttpReply> {
        let envelope = self.envelope(method, params);
        let name = mcp_name(method, &envelope["params"]);
        let body = envelope.to_string();
        self.send(
            "POST",
            "",
            &self.headers_for(method, name.as_deref()),
            Some(&body),
        )
    }

    /// Sends a well-formed MCP request and returns the JSON-RPC `result` object.
    pub fn rpc(&self, method: &str, params: Value) -> Result<Value> {
        let reply = self.rpc_raw(method, params)?;
        let body = reply.json()?;
        ensure!(
            reply.status == 200,
            "{method} returned HTTP {}: {body}",
            reply.status
        );
        let result = body
            .get("result")
            .cloned()
            .with_context(|| format!("{method} returned no result: {body}"))?;
        ensure!(
            result.get("resultType") == Some(&json!("complete")),
            "{method} result has no resultType=complete: {result}"
        );
        Ok(result)
    }

    pub fn ping(&self) -> Result<()> {
        self.rpc("ping", json!({})).map(|_| ())
    }

    /// Calls a tool and checks the shape of the tool result.
    pub fn call_tool(&self, tool: &str, arguments: Value) -> Result<ToolReply> {
        let result = self.rpc("tools/call", json!({"name": tool, "arguments": arguments}))?;
        let is_error = result
            .get("isError")
            .and_then(Value::as_bool)
            .with_context(|| format!("tool result has no isError flag: {result}"))?;
        let structured = result
            .get("structuredContent")
            .cloned()
            .with_context(|| format!("tool result has no structuredContent: {result}"))?;
        let content = result
            .get("content")
            .and_then(Value::as_array)
            .with_context(|| format!("tool result has no content array: {result}"))?;
        let [text_item] = content.as_slice() else {
            bail!("tool result must have exactly one content item: {result}");
        };
        ensure!(
            text_item.get("type") == Some(&json!("text")),
            "content item is not text"
        );
        let text = text_item
            .get("text")
            .and_then(Value::as_str)
            .context("text content has no text")?;
        let parsed: Value = serde_json::from_str(text)
            .with_context(|| format!("text content is not JSON: {text}"))?;
        ensure!(
            parsed == structured,
            "text content does not match structuredContent:\n{text}\n{structured}"
        );
        Ok(ToolReply {
            is_error,
            structured,
        })
    }

    fn take_id(&self) -> u64 {
        let id = self.next_id.get();
        self.next_id.set(id + 1);
        id
    }
}

/// Returns the MCP request metadata that the server requires.
pub fn meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientInfo": {
            "name": env!("CARGO_PKG_NAME"),
            "version": env!("CARGO_PKG_VERSION"),
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

fn mcp_name(method: &str, params: &Value) -> Option<String> {
    let key = match method {
        "tools/call" => "name",
        "resources/read" => "uri",
        _ => return None,
    };
    params.get(key).and_then(Value::as_str).map(str::to_string)
}
