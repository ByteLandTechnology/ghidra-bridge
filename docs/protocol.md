# Protocol Specification

Ghidra Bridge supports two transports: WebSocket JSON-RPC 2.0 and MCP Streamable HTTP `2026-07-28`.
The unified registry defines 56 public dotted methods.
WebSocket publishes all 56 methods.
MCP publishes 55 methods, and does not publish `interface.get`.

## WebSocket JSON-RPC 2.0

WebSocket messages follow the JSON-RPC 2.0 specification.
Clients communicate with the bridge through full-duplex socket connections.

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
- `method` must match one of the 56 public dotted methods.
- `params` must be a JSON object that matches the method schema.
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
- `400`: Absent upgrade headers, an unsupported WebSocket version, or a token in the query string.
- `401`: Absent or invalid bearer token.
- `404`: The request path does not match the configured `path`.
- `405`: The upgrade request does not use GET.
- `409`: Another client is already connected.

### WebSocket Close Codes

The server closes the socket with these status codes:
- `1000`: Normal closure.
- `1001`: The server stops.
- `1003`: The client sent a fragmented text message or an unsupported frame.

## Model Context Protocol (MCP)

The bridge implements MCP Streamable HTTP protocol version `2026-07-28`.
The server does not use MCP sessions and does not send server-sent events.

### HTTP Request Rules

The MCP HTTP server handles requests:
- **POST**: Dispatches JSON-RPC 2.0 requests.
- **OPTIONS**: Handles CORS preflight requests and returns status `204`.
- **GET**: The server returns status `405` with `Allow: POST, OPTIONS`.
- **Other methods**: The server returns status `405`.
- **Origin**: A request with an `Origin` header that is not a loopback host or the configured `host` returns status `403`.
- **Content Type**: A POST request must send `Content-Type: application/json`. Other values return status `415`.
- **Notifications**: A request without `id` returns status `202` with no body.

### Initialization Compatibility

Clients can also use `initialize` with `2025-06-18` or `2025-11-25`.
The response includes `protocolVersion`, `serverInfo`, and `capabilities`.
An unsupported requested version negotiates `2025-11-25`.
Initialization without modern request metadata selects this compatibility path.
The version header is optional.
An unsupported header returns HTTP `400`.

Subsequent requests must send the negotiated `MCP-Protocol-Version`.
An absent or unsupported version returns HTTP `400`.
These requests do not require the modern `_meta` fields or `Mcp-Method`/`Mcp-Name` headers. `notifications/initialized` returns `202` without a body.

### Request Metadata (`2026-07-28`)

Every `2026-07-28` POST request must include protocol data in `params._meta`.
This data must contain the version and client capabilities.
Client information is optional:

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

These requests must also send these HTTP headers:
- `MCP-Protocol-Version`: The same value as `io.modelcontextprotocol/protocolVersion`.
- `Mcp-Method`: The same value as the JSON-RPC `method`.
- `Mcp-Name`: For `tools/call`, the tool name. For `resources/read`, the resource URI. Other methods do not use this header.

A header value can use the form `=?base64?<base64 text>?=` for text that is not plain ASCII.

The server returns these errors for bad metadata:
- Absent required `_meta` fields: HTTP `400`, code `-32602`.
- An unsupported protocol version: HTTP `400`, code `-32022`. The `data` property lists the supported versions.
- A header that does not match the request body: HTTP `400`, code `-32020`.

### Supported MCP Methods

The server handles these MCP methods:
- `initialize`: Negotiates a version for initialization-based clients, as described above.
- `server/discover`: Returns server identification and capabilities.
- `ping`: Checks server health in initialization-based versions.
  The bridge keeps this compatibility method in `2026-07-28`.
- `tools/list`: Returns tool schemas for all 56 bridge tools (`ghidra_help` and 55 operation tools).
- `tools/call`: Executes a tool operation and returns structured content.
- `resources/list`: Lists available resources, such as `ghidra-bridge://contracts/mcp-tools`.
- `resources/read`: Reads contract resource content.
- `resources/templates/list`: Returns an empty template list.

Other methods return HTTP `404` with code `-32601`.
Every successful `2026-07-28` result includes `"resultType": "complete"`. Initialization-based `ping` returns `{}`.
Modern list, discovery, and read results include `ttlMs: 0` and `cacheScope: "private"`.
In `2026-07-28`, an unknown resource URI returns HTTP `400` and code `-32602`.
In initialization-based versions, it returns HTTP `404` and code `-32002`.

Errors without an identifiable request ID omit `id` from `2025-11-25` onward.
For `2025-06-18`, the bridge follows the JSON-RPC `id: null` rule.
The MCP error schema for that version cannot represent this case.

### Tool Call Convention

`tools/list` publishes 56 underscored tools:
- `ghidra_help`: Finds domains, lists operations with schemas and effects, and shows single-operation contracts.
- 55 Per-Operation Tools across 14 domains (`bridge` through `batch`), named `<prefix>_<domain>_<operation>` with dots replaced by underscores. Examples include `ghidra_memory_read` and `ghidra_function_local_variable_patch`.

Each operation tool publishes a flattened parameter schema without `oneOf`, `anyOf`, `allOf`, `$ref`, `$defs`, or `additionalProperties`. It also publishes exact safety hints (`readOnlyHint`, `destructiveHint`, `idempotentHint`) in `tools/list`.
`interface.get` is available only through WebSocket.

### Tool Name Prefix and Multi-Server Tool Budgets

Every listed tool name starts with a prefix and an underscore. The default prefix is `ghidra`.
Set the `tool_prefix` startup argument to change it, for example `tool_prefix=sample`.
Then the tool names include `sample_help` and `sample_program_get`.
Use a different prefix for each bridge when one MCP client connects to more than one bridge.

The prefix starts with a letter and has 1 to 34 letters, digits, `_`, or `-`. This rule keeps every tool name within the 64-character limit of strict MCP providers.
The server rejects a tool name with a different prefix.
In `ghidra_help`, the `domain` argument accepts the domain tool name (`ghidra_memory`) or the bare domain name (`memory`).
The examples in this document use the default prefix.

Each bridge lists 56 tools: two bridges publish 112 tools, and three bridges publish 168 tools. Three bridges exceed the 128-tool cap in strict MCP clients. Keep multi-server sessions within your client tool budget, or use `ghidra-mcp` for multiple binaries.

`ghidra_help` accepts optional `domain` and `operation` arguments:
- No arguments: Returns the list of domain names (`ghidra_bridge` through `ghidra_batch`).
- `domain`: Returns the operations of one domain, each with its `name`, `tool`, `method`, `description`, `effects`, `inputSchema`, and `outputSchema`.
- `domain` and `operation`: Returns the `tool`, `method`, `description`, `effects`, `inputSchema`, and `outputSchema` of one operation.

To execute an operation directly, call its per-operation tool with the operation parameters at the top level of `arguments`.
For example, call `ghidra_memory_read` for the `memory.read` method:

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
    "name": "ghidra_memory_read",
    "arguments": {
      "selector": {"address": "ram:00100000"},
      "length": 4
    }
  }
}
```

For compatibility with earlier clients, `tools/call` also accepts unlisted `<prefix>_<domain>` and `<prefix>.<domain>` requests with `operation` and `params`. For example, `"name": "ghidra_memory"` accepts `{"operation": "read", "params": {"selector": {"address": "ram:00100000"}, "length": 4}}`.

The server returns both text and structured content:

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
Invalid operation parameters, or an unknown operation or unexpected wrapper field on a legacy `<prefix>_<domain>` call, return a tool error.

## Authentication and Security

- **Loopback Default**: Listeners bind to `127.0.0.1` by default. A loopback listener without `token` does not require authentication.
- **External Listener**: A listener on an external network interface requires `token`.
- **Authorization Header**: Send credentials through `Authorization: Bearer <token>`.
- **Query Token Rejection**: The server rejects tokens in query strings with HTTP 400.
- **Log Redaction**: Secret tokens never appear in server log files.

## Bounded Address Scans and Cursors

List methods support bounded scans across memory addresses:
- `scan.range`: Supplies `start` and `end` address bounds.
- `scan.timeout_ms`: Sets a time limit from 100 to 60000 milliseconds. The default is 1000.
- `page.limit`: Sets a maximum of 1000 items on each page.

When a query stops before completion:
- The response returns the items that the server collected.
- The `scan.complete` property reports `false`.
- The `scan.stop_reason` property reports `limit` or `timeout`.
- The `next_cursor` property holds the resumption token.
- Pass the token as `page.cursor` in the next request to continue the scan.
