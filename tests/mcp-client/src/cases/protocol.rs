//! MCP Streamable HTTP protocol cases: methods, metadata, headers, and authentication.

use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde_json::{json, Value};

use super::Case;
use crate::context::TestContext;
use crate::mcp::{HttpReply, PROTOCOL_VERSION};

const TOOLS_RESOURCE: &str = "ghidra-bridge://contracts/mcp-tools";

pub fn cases() -> Vec<Case> {
    vec![
        Case::new("protocol.server_discover", server_discover),
        Case::new("protocol.ping", ping),
        Case::new("protocol.resources", resources),
        Case::new("protocol.unknown_method", unknown_method),
        Case::new("protocol.notification", notification),
        Case::new("protocol.http_methods", http_methods),
        Case::new("protocol.content_type", content_type),
        Case::new("protocol.invalid_json", invalid_json),
        Case::new("protocol.origin", origin),
        Case::new("protocol.authorization", authorization),
        Case::new("protocol.metadata", metadata),
        Case::new("protocol.headers", headers),
        Case::new("protocol.tool_call_errors", tool_call_errors),
        Case::new("protocol.tool_prefix", tool_prefix),
    ]
}

fn server_discover(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.client.rpc("server/discover", json!({}))?;
    ensure!(
        result["supportedVersions"] == json!([PROTOCOL_VERSION]),
        "unexpected supportedVersions: {result}"
    );
    ensure!(
        result.pointer("/capabilities/tools").is_some(),
        "no tools capability: {result}"
    );
    ensure!(
        result.pointer("/capabilities/resources").is_some(),
        "no resources capability"
    );
    let server = result
        .pointer("/_meta/io.modelcontextprotocol~1serverInfo")
        .context("no serverInfo in _meta")?;
    ensure!(
        server["name"] == json!("ghidra-bridge"),
        "unexpected server name: {server}"
    );
    ensure!(
        server["version"].as_str().is_some(),
        "server version is missing"
    );
    Ok(())
}

fn ping(ctx: &mut TestContext) -> Result<()> {
    let result = ctx.client.rpc("ping", json!({}))?;
    ensure!(
        result == json!({"resultType": "complete"}),
        "unexpected ping result: {result}"
    );
    Ok(())
}

fn resources(ctx: &mut TestContext) -> Result<()> {
    let listed = ctx.client.rpc("resources/list", json!({}))?;
    let resources = listed["resources"]
        .as_array()
        .context("no resources array")?;
    ensure!(resources.len() == 1, "expected one resource: {listed}");
    ensure!(
        resources[0]["uri"] == json!(TOOLS_RESOURCE),
        "unexpected resource: {listed}"
    );
    ensure!(
        resources[0]["mimeType"] == json!("application/json"),
        "unexpected mimeType"
    );

    let read = ctx
        .client
        .rpc("resources/read", json!({"uri": TOOLS_RESOURCE}))?;
    let contents = read["contents"].as_array().context("no contents array")?;
    ensure!(contents.len() == 1, "expected one content item: {read}");
    let contract: Value =
        serde_json::from_str(contents[0]["text"].as_str().context("no resource text")?)?;
    ensure!(
        contract["protocol_version"] == json!(PROTOCOL_VERSION),
        "wrong protocol_version"
    );
    let tools = ctx.client.rpc("tools/list", json!({}))?;
    ensure!(
        contract["tools"] == tools["tools"],
        "the resource does not match tools/list"
    );

    let templates = ctx.client.rpc("resources/templates/list", json!({}))?;
    ensure!(
        templates["resourceTemplates"] == json!([]),
        "templates are not empty: {templates}"
    );

    let reply = ctx
        .client
        .rpc_raw("resources/read", json!({"uri": "ghidra-bridge://missing"}))?;
    expect_http(&reply, 404, Some(-32002))
}

/// `prompts/list` and other methods that the server does not implement.
fn unknown_method(ctx: &mut TestContext) -> Result<()> {
    for method in ["prompts/list", "initialize", "tools/unknown"] {
        let reply = ctx.client.rpc_raw(method, json!({}))?;
        expect_http(&reply, 404, Some(-32601)).with_context(|| format!("method {method}"))?;
    }
    Ok(())
}

/// A request without `id` is a notification and gets 202 with no body.
fn notification(ctx: &mut TestContext) -> Result<()> {
    let mut envelope = ctx.client.envelope("ping", json!({}));
    envelope.as_object_mut().context("envelope")?.remove("id");
    let reply = ctx.client.send(
        "POST",
        "",
        &ctx.client.headers_for("ping", None),
        Some(&envelope.to_string()),
    )?;
    ensure!(
        reply.status == 202,
        "expected 202, got {}: {}",
        reply.status,
        reply.body
    );
    ensure!(
        reply.body.is_empty(),
        "notification reply has a body: {}",
        reply.body
    );
    Ok(())
}

fn http_methods(ctx: &mut TestContext) -> Result<()> {
    let auth = auth_header(ctx);
    let reply = ctx.client.send("GET", "", &auth, None)?;
    ensure!(reply.status == 405, "GET returned {}", reply.status);
    ensure!(
        reply.header("Allow") == Some("POST, OPTIONS"),
        "GET Allow: {:?}",
        reply.header("Allow")
    );

    let reply = ctx.client.send("OPTIONS", "", &auth, None)?;
    ensure!(reply.status == 204, "OPTIONS returned {}", reply.status);
    ensure!(
        reply.header("Access-Control-Allow-Methods").is_some(),
        "OPTIONS has no CORS headers"
    );

    let reply = ctx.client.send("PUT", "", &auth, Some("{}"))?;
    expect_http(&reply, 405, Some(-32600))?;
    ensure!(
        reply.header("Allow") == Some("POST, OPTIONS"),
        "PUT Allow: {:?}",
        reply.header("Allow")
    );
    Ok(())
}

fn content_type(ctx: &mut TestContext) -> Result<()> {
    let body = ctx.client.envelope("ping", json!({})).to_string();
    let headers = replace_header(
        ctx.client.headers_for("ping", None),
        "Content-Type",
        Some("text/plain"),
    );
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    expect_http(&reply, 415, Some(-32600))
}

fn invalid_json(ctx: &mut TestContext) -> Result<()> {
    let headers = ctx.client.headers_for("ping", None);
    let reply = ctx
        .client
        .send("POST", "", &headers, Some("{\"jsonrpc\":"))?;
    expect_http(&reply, 400, Some(-32700))?;
    let reply = ctx.client.send("POST", "", &headers, Some("[]"))?;
    expect_http(&reply, 400, Some(-32600))?;

    let mut envelope = ctx.client.envelope("ping", json!({}));
    envelope["jsonrpc"] = json!("1.0");
    let reply = ctx
        .client
        .send("POST", "", &headers, Some(&envelope.to_string()))?;
    expect_http(&reply, 400, Some(-32600))
}

/// Browsers may call the server only from a loopback origin.
fn origin(ctx: &mut TestContext) -> Result<()> {
    let body = ctx.client.envelope("ping", json!({})).to_string();
    let mut headers = ctx.client.headers_for("ping", None);
    headers.push(("Origin".into(), "http://example.com".into()));
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    ensure!(
        reply.status == 403,
        "foreign origin returned {}",
        reply.status
    );

    let body = ctx.client.envelope("ping", json!({})).to_string();
    let headers = replace_header(headers, "Origin", Some("http://localhost:8080"));
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    ensure!(
        reply.status == 200,
        "loopback origin returned {}: {}",
        reply.status,
        reply.body
    );
    ensure!(
        reply.header("Access-Control-Allow-Origin") == Some("http://localhost:8080"),
        "no CORS origin header for a loopback origin"
    );
    Ok(())
}

fn authorization(ctx: &mut TestContext) -> Result<()> {
    ensure!(
        ctx.client.token().is_some(),
        "the runner must start the bridge with a token"
    );
    let body = ctx.client.envelope("ping", json!({})).to_string();
    let headers = ctx.client.headers_for("ping", None);

    let without = replace_header(headers.clone(), "Authorization", None);
    let reply = ctx.client.send("POST", "", &without, Some(&body))?;
    expect_http(&reply, 401, Some(-32001))?;
    ensure!(
        reply.header("WWW-Authenticate") == Some("Bearer"),
        "no WWW-Authenticate header"
    );

    let wrong = replace_header(headers.clone(), "Authorization", Some("Bearer wrong-token"));
    let reply = ctx.client.send("POST", "", &wrong, Some(&body))?;
    expect_http(&reply, 401, Some(-32001))?;

    let query = format!("?token={}", ctx.client.token().unwrap_or_default());
    let reply = ctx.client.send("POST", &query, &headers, Some(&body))?;
    expect_http(&reply, 400, Some(-32600))
}

fn metadata(ctx: &mut TestContext) -> Result<()> {
    let headers = ctx.client.headers_for("ping", None);

    // No _meta at all.
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "params": {}}).to_string();
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    expect_http(&reply, 400, Some(-32602))?;

    // _meta without client capabilities.
    let mut envelope = ctx.client.envelope("ping", json!({}));
    envelope["params"]["_meta"]
        .as_object_mut()
        .context("_meta")?
        .remove("io.modelcontextprotocol/clientCapabilities");
    let reply = ctx
        .client
        .send("POST", "", &headers, Some(&envelope.to_string()))?;
    expect_http(&reply, 400, Some(-32602))?;

    // An unsupported protocol version lists the supported ones.
    let mut envelope = ctx.client.envelope("ping", json!({}));
    envelope["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("2024-11-05");
    let old = replace_header(headers, "MCP-Protocol-Version", Some("2024-11-05"));
    let reply = ctx
        .client
        .send("POST", "", &old, Some(&envelope.to_string()))?;
    expect_http(&reply, 400, Some(-32022))?;
    let data = reply.json()?["error"]["data"].clone();
    ensure!(
        data == json!({"requested": "2024-11-05", "supported": [PROTOCOL_VERSION]}),
        "unexpected version error data: {data}"
    );
    Ok(())
}

/// The protocol headers must repeat values from the body.
fn headers(ctx: &mut TestContext) -> Result<()> {
    let ping_headers = ctx.client.headers_for("ping", None);
    let body = || ctx.client.envelope("ping", json!({})).to_string();
    for (header, value) in [
        ("MCP-Protocol-Version", None),
        ("MCP-Protocol-Version", Some("2025-06-18")),
        ("Mcp-Method", None),
        ("Mcp-Method", Some("tools/list")),
    ] {
        let changed = replace_header(ping_headers.clone(), header, value);
        let reply = ctx.client.send("POST", "", &changed, Some(&body()))?;
        expect_http(&reply, 400, Some(-32020)).with_context(|| format!("{header}={value:?}"))?;
    }

    let help = ctx.client.wire_name("ghidra.help");
    let program = ctx.client.wire_name("ghidra.program");
    let params = json!({"name": "ghidra.help", "arguments": {}});
    let call_headers = ctx.client.headers_for("tools/call", Some(&help));
    for value in [None, Some(program.as_str())] {
        let changed = replace_header(call_headers.clone(), "Mcp-Name", value);
        let body = ctx
            .client
            .envelope("tools/call", params.clone())
            .to_string();
        let reply = ctx.client.send("POST", "", &changed, Some(&body))?;
        expect_http(&reply, 400, Some(-32020)).with_context(|| format!("Mcp-Name={value:?}"))?;
    }

    // A base64-encoded header value is decoded before the comparison.
    let encoded = base64::engine::general_purpose::STANDARD.encode(&help);
    let changed = replace_header(
        call_headers,
        "Mcp-Name",
        Some(&format!("=?base64?{encoded}?=")),
    );
    let body = ctx.client.envelope("tools/call", params).to_string();
    let reply = ctx.client.send("POST", "", &changed, Some(&body))?;
    ensure!(
        reply.status == 200,
        "base64 Mcp-Name returned {}: {}",
        reply.status,
        reply.body
    );
    Ok(())
}

fn tool_call_errors(ctx: &mut TestContext) -> Result<()> {
    // An unknown tool is a JSON-RPC error.
    let reply = ctx.client.rpc_raw(
        "tools/call",
        json!({"name": "ghidra.missing", "arguments": {"operation": "get", "params": {}}}),
    )?;
    expect_http(&reply, 400, Some(-32602))?;

    // A missing tool name is a JSON-RPC error.
    let reply = ctx.client.rpc_raw("tools/call", json!({"arguments": {}}))?;
    ensure!(
        reply.status == 400,
        "a call without a name returned {}",
        reply.status
    );

    // Everything else is a tool error.
    ctx.fail_arguments(
        "ghidra.program",
        json!({"operation": "missing", "params": {}}),
    )?;
    ctx.fail_arguments(
        "ghidra.program",
        json!({"operation": "get", "params": {}, "extra": 1}),
    )?;
    ctx.fail_arguments("ghidra.program", json!({"params": {}}))?;
    let error = ctx.fail("ghidra.program", "get", json!({"unknown_field": true}))?;
    ensure!(
        error["status"] == json!(400),
        "an unknown field must be a 400 error: {error}"
    );
    let error = ctx.fail("ghidra.memory", "read", json!({"selector": {"address": 5}}))?;
    ensure!(
        error["status"] == json!(400),
        "a wrong type must be a 400 error: {error}"
    );
    ensure!(
        error["target"].as_str().is_some(),
        "a validation error must have a target: {error}"
    );
    Ok(())
}

/// Every tool name uses the configured prefix, and names with another prefix do not work.
fn tool_prefix(ctx: &mut TestContext) -> Result<()> {
    let prefix = ctx.client.tool_prefix().to_string();
    let tools = ctx.client.rpc("tools/list", json!({}))?;
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .context("no tools array")?
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .collect();
    ensure!(
        names
            .iter()
            .all(|name| name.starts_with(&format!("{prefix}."))),
        "a tool name does not use the prefix {prefix}: {names:?}"
    );

    // A client that connects to several bridges must not reach this one with another prefix.
    let other = if prefix == "ghidra" {
        "other"
    } else {
        "ghidra"
    };
    let foreign = format!("{other}.program");
    let params = json!({"name": foreign, "arguments": {"operation": "get", "params": {}}});
    let body = ctx.client.envelope_exact("tools/call", params).to_string();
    let headers = ctx.client.headers_for("tools/call", Some(&foreign));
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    expect_http(&reply, 400, Some(-32602))?;

    let help = ctx.client.wire_name("ghidra.help");
    let params = json!({"name": help, "arguments": {"domain": format!("{other}.memory")}});
    let body = ctx.client.envelope_exact("tools/call", params).to_string();
    let headers = ctx.client.headers_for("tools/call", Some(&help));
    let reply = ctx.client.send("POST", "", &headers, Some(&body))?;
    let result = reply.json()?;
    ensure!(
        result.pointer("/result/isError") == Some(&json!(true)),
        "help accepted a domain with another prefix: {result}"
    );
    Ok(())
}

fn auth_header(ctx: &TestContext) -> Vec<(String, String)> {
    ctx.client
        .token()
        .map(|token| vec![("Authorization".to_string(), format!("Bearer {token}"))])
        .unwrap_or_default()
}

fn replace_header(
    mut headers: Vec<(String, String)>,
    name: &str,
    value: Option<&str>,
) -> Vec<(String, String)> {
    headers.retain(|(key, _)| !key.eq_ignore_ascii_case(name));
    if let Some(value) = value {
        headers.push((name.to_string(), value.to_string()));
    }
    headers
}

fn expect_http(reply: &HttpReply, status: u16, rpc_code: Option<i64>) -> Result<()> {
    ensure!(
        reply.status == status,
        "expected HTTP {status}, got {}: {}",
        reply.status,
        reply.body
    );
    if let Some(code) = rpc_code {
        let actual = reply.rpc_error_code()?;
        ensure!(
            actual == code,
            "expected JSON-RPC code {code}, got {actual}: {}",
            reply.body
        );
    }
    Ok(())
}
