# Protocol Specification

Ghidra Bridge supports two transports: WebSocket JSON-RPC 2.0 and MCP Streamable HTTP `2026-07-28`.
The unified registry defines 53 public dotted methods.
WebSocket publishes all 53 methods. MCP publishes 52 methods; `interface.get` is WebSocket only.

## WebSocket JSON-RPC 2.0

WebSocket messages follow the JSON-RPC 2.0 specification.
Clients communicate with the bridge over full-duplex socket connections.

### Request Envelope

Clients send requests as JSON objects:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "method": "program.get",
  "params": {}
}
```

The server validates every field:
- `jsonrpc` must equal `"2.0"`.
- `id` must be a string or integer identifier.
- `method` must match one of the 53 public dotted methods.
- `params` must be a JSON object matching the method schema.
- The server rejects unknown fields and invalid data types.

### Ready Notification

When the connection becomes active, the server sends a ready notification:

```json
{
  "jsonrpc": "2.0",
  "method": "ghidra.ready",
  "params": {
    "session_id": "demo",
    "program_name": "example.bin"
  }
}
```

### Success Response

Successful requests return a result envelope:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "result": {
    "name": "example.bin",
    "language_id": "x86:LE:64:default",
    "compiler_spec_id": "gcc"
  }
}
```

### Error Response

Failed requests return an error envelope:

```json
{
  "jsonrpc": "2.0",
  "id": "req-1",
  "error": {
    "code": -32000,
    "message": "address not found",
    "data": {
      "status": 404,
      "code": "not_found",
      "message": "address not found",
      "target": "/params/selector/address",
      "details": {}
    }
  }
}
```

The `target` property uses RFC 6901 JSON pointer syntax.
Stack traces and internal exceptions never cross the network.

### Protocol Errors

The server replies with an error envelope for a bad message and keeps the socket open:
- Invalid JSON text returns code `-32700`.
- A message that is not a valid JSON-RPC 2.0 request returns code `-32600`.
- A method failure returns code `-32000`. The `data` property holds the bridge error.

### Handshake Errors

The server rejects a bad upgrade request with an HTTP status before the socket opens:
- `400`: Missing upgrade headers, an unsupported WebSocket version, or a token in the query string.
- `401`: Missing or invalid bearer token.
- `404`: The request path does not match the configured `path`.
- `405`: The upgrade request does not use GET.
- `409`: Another client is already connected.

### WebSocket Close Codes

The server closes the socket with these status codes:
- `1000`: Normal closure.
- `1001`: The server shuts down.
- `1003`: The client sent a fragmented text message or an unsupported frame.

## Model Context Protocol (MCP)

The bridge implements MCP Streamable HTTP protocol version `2026-07-28`.
The server does not use MCP sessions and does not send server-sent events.

### HTTP Request Rules

The MCP HTTP server handles incoming requests:
- **POST**: Dispatches incoming JSON-RPC 2.0 requests.
- **OPTIONS**: Handles CORS preflight requests and returns status `204`.
- **GET**: The server returns status `405` with `Allow: POST, OPTIONS`.
- **Other methods**: The server returns status `405`.
- **Origin**: A request with an `Origin` header that is not a loopback host or the configured `host` returns status `403`.
- **Content Type**: A POST request must send `Content-Type: application/json`. Other values return status `415`.
- **Notifications**: A request without `id` returns status `202` with no body.

### Request Metadata

Every POST request must include MCP metadata in `params._meta`:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ping",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1.0.0"},
      "io.modelcontextprotocol/clientCapabilities": {}
    }
  }
}
```

Every POST request must also send these HTTP headers:
- `MCP-Protocol-Version`: The same value as `io.modelcontextprotocol/protocolVersion`.
- `Mcp-Method`: The same value as the JSON-RPC `method`.
- `Mcp-Name`: For `tools/call`, the tool name. For `resources/read`, the resource URI. Other methods do not use this header.

A header value can use the form `=?base64?<base64 text>?=` for text that is not plain ASCII.

The server returns these errors for bad metadata:
- Missing `_meta` fields: HTTP `400`, code `-32602`.
- An unsupported protocol version: HTTP `400`, code `-32022`. The `data` property lists the supported versions.
- A header that does not match the request body: HTTP `400`, code `-32020`.

### Supported MCP Methods

The server handles these MCP methods:
- `server/discover`: Returns server identification and capabilities.
- `ping`: Verifies connection health and returns completion status.
- `tools/list`: Returns tool schemas for all 15 bridge tools.
- `tools/call`: Executes a tool operation and returns structured content.
- `resources/list`: Lists available resources, including `ghidra-bridge://contracts/mcp-tools`.
- `resources/read`: Reads contract resource content.
- `resources/templates/list`: Returns an empty template list.

Other methods return HTTP `404` with code `-32601`.
Every successful result includes `"resultType": "complete"`.

### Tool Call Convention

MCP organizes operations into 15 tools:
- `ghidra.help`: Discovers domains, lists operations, and shows schemas.
- 14 Domain Tools: `ghidra.bridge`, `ghidra.program`, `ghidra.address`, `ghidra.memory`, `ghidra.listing`, `ghidra.global_variable`, `ghidra.function`, `ghidra.analysis`, `ghidra.decompilation`, `ghidra.symbol`, `ghidra.reference`, `ghidra.comment`, `ghidra.data_type`, `ghidra.batch`.

The domain tools expose 52 methods. `interface.get` is available only through WebSocket.

### Tool Name Prefix

Every tool name starts with a prefix and a dot. The default prefix is `ghidra`.
Set the `tool_prefix` startup argument to change it, for example `tool_prefix=sample`.
Then the tools are `sample.help`, `sample.program`, and so on.
Use a different prefix for each bridge when one MCP client connects to more than one bridge.

The prefix starts with a letter and has 1 to 64 letters, digits, `_`, or `-`.
The server rejects a tool name with a different prefix.
In `ghidra.help`, the `domain` argument accepts the full tool name or the domain name without the prefix, such as `memory`.
The examples in this document use the default prefix.

`ghidra.help` accepts optional `domain` and `operation` arguments:
- No arguments: Returns the list of domain tools.
- `domain`: Returns the operation names of one domain tool.
- `domain` and `operation`: Returns the method name, description, effects, `inputSchema`, and `outputSchema` of one operation.

To execute an operation, call its domain tool with `operation` and `params`.
The `operation` value is the operation name in the domain tool, not the dotted method name.
For example, the `memory.read` method is the `read` operation of `ghidra.memory`:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "method": "tools/call",
  "params": {
    "_meta": {
      "io.modelcontextprotocol/protocolVersion": "2026-07-28",
      "io.modelcontextprotocol/clientInfo": {"name": "example-client", "version": "1.0.0"},
      "io.modelcontextprotocol/clientCapabilities": {}
    },
    "name": "ghidra.memory",
    "arguments": {
      "operation": "read",
      "params": {
        "selector": {"address": "ram:00100000"},
        "length": 4
      }
    }
  }
}
```

The response returns both text and structured content:

```json
{
  "jsonrpc": "2.0",
  "id": "call-1",
  "result": {
    "resultType": "complete",
    "content": [
      {
        "type": "text",
        "text": "{\"operation\":\"read\",\"result\":{\"address\":\"ram:00100000\",\"bytes\":{\"encoding\":\"hex\",\"data\":\"7f454c46\",\"length\":4}}}"
      }
    ],
    "structuredContent": {
      "operation": "read",
      "result": {
        "address": "ram:00100000",
        "bytes": {"encoding": "hex", "data": "7f454c46", "length": 4}
      }
    },
    "isError": false
  }
}
```

When an operation fails, the server returns HTTP `200` with `"isError": true`.
The `structuredContent` object holds the bridge error with `status`, `code`, `message`, `target`, and `details`.
An unknown tool name returns HTTP `400` with code `-32602`.
An unknown operation, or an argument other than `operation` and `params`, returns a tool error.

## Authentication and Security

- **Loopback Default**: Listeners bind to `127.0.0.1` by default. A loopback listener without `token` does not require authentication.
- **Remote Binding**: Binding to any external network interface requires `token`.
- **Authorization Header**: Send credentials via `Authorization: Bearer <token>`.
- **Query Tokens Rejected**: The server rejects tokens in query strings with HTTP 400.
- **Log Masking**: Secret tokens never appear in server log files.

## Bounded Address Scans and Cursors

Listing methods support bounded scanning over memory addresses:
- `scan.range`: Supplies `start` and `end` address bounds.
- `scan.timeout_ms`: Sets a maximum execution budget from 100 to 60000 milliseconds. The default is 1000.
- `page.limit`: Sets the maximum items per page up to 1000 items.

When a query stops before completion:
- The response returns collected items.
- The `scan.complete` property reports `false`.
- The `scan.stop_reason` property reports `limit` or `timeout`.
- The `next_cursor` property holds the resumption token.
- Pass the token as `page.cursor` in the next request to continue the scan.
