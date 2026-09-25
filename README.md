# Ghidra Bridge

[English](README.md) | [中文](README.zh-CN.md) | [日本語](README.ja-JP.md)

Ghidra Bridge gives network access to an active Ghidra program.
The runtime runs on Java 21 and supports Ghidra 12.1.
It exposes two transports: WebSocket JSON-RPC 2.0 and MCP Streamable HTTP `2026-07-28`.
The runtime JAR has zero third-party dependencies.

## Key Features

- **Dual Transports**: Access Ghidra through WebSocket JSON-RPC 2.0 or MCP Streamable HTTP.
- **Unified Catalog**: One typed registry defines 53 public dotted methods. WebSocket exposes all 53. MCP exposes 52 of them; `interface.get` is WebSocket only.
- **Bounded Scans**: Address-ordered listings support cooperative cancellation and cursor pagination.
- **Atomic Transactions**: Execute batch operations with automatic rollback on error.
- **Headless Mode**: Run the bridge in Ghidra headless scripts without GUI interaction.

## Build the Scripts

Set `GHIDRA_INSTALL_DIR` to your Ghidra installation path.
Then build the scripts with the Gradle wrapper:

```bash
./gradlew buildGhidraScript
```

The build task creates three files in `build/ghidra-script/`:

```text
Bridge.java
GhidraMcp.java
ghidra-bridge.jar
```

Keep these three files in the same directory.
The loader scripts locate `ghidra-bridge.jar` relative to their file path.

## Start the Bridge

### Run in the Ghidra GUI

1. Open a binary in the Ghidra CodeBrowser tool.
2. Open the Script Manager window.
3. Add `build/ghidra-script/` to your script directories.
4. Run `Bridge.java` for WebSocket or `GhidraMcp.java` for MCP.
5. Enter configuration arguments in the prompt window.

### Run in Ghidra Headless Mode

You can run `GhidraMcp.java` or `Bridge.java` as a post-script in headless mode.
Create a project directory, then import and analyze the target binary.
Do not use project paths with dot-prefixed directory names like `.cache`.

```bash
mkdir -p /path/to/projects
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -import /path/to/target_binary \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

The post-script serves requests until you stop the process.
To open an existing project file without re-analysis, use `-process` with `-noanalysis`:

```bash
"$GHIDRA_INSTALL_DIR/support/analyzeHeadless" /path/to/projects demo \
  -process target_binary -noanalysis \
  -scriptPath "$PWD/build/ghidra-script" \
  -postScript GhidraMcp.java host=127.0.0.1 port=8766 path=/mcp session_id=demo
```

## Configuration Arguments

Configure the bridge with strict `key=value` pairs.
The launcher rejects unknown arguments, duplicate arguments, and camelCase keys.

```text
# Embedded WebSocket server
host=127.0.0.1 port=8765 path=/ws/agent session_id=demo

# Outbound WebSocket client
ws_url=ws://127.0.0.1:8765/ws/agent session_id=demo token=secret

# MCP HTTP server
host=127.0.0.1 port=8766 path=/mcp session_id=demo token=secret

# Second MCP HTTP server with its own tool names
host=127.0.0.1 port=8767 path=/mcp session_id=other tool_prefix=other
```

### Parameter Reference

| Parameter | Default | Description |
|---|---|---|
| `host` | `127.0.0.1` | Local network interface address to listen on. |
| `port` | `8765` (WS) / `8766` (MCP) | TCP port number for the HTTP or WebSocket server. WebSocket uses the default only when `ws_url` is not set. |
| `path` | `/ws/agent` (WS) / `/mcp` (MCP) | URL path endpoint for request dispatch. |
| `session_id` | Program name | Unique identifier string for this active session. |
| `token` | *(none)* | Shared secret token for bearer authentication. |
| `ws_url` | *(none)* | Remote WebSocket URL when operating as an outbound client. |
| `tool_prefix` | `ghidra` | MCP only. First part of every tool name, such as `ghidra` in `ghidra.program`. Use a different value for each server that one client connects to. |
| `jar` | *(auto)* | Path to `ghidra-bridge.jar` if moved away from script file. |

## Security Rules

The bridge enforces strict security boundaries:

- **Loopback Default**: Listeners bind to `127.0.0.1` by default.
- **Mandatory Token**: A listener bound to a non-loopback interface requires `token`.
- **Bearer Header**: Inbound requests must send `Authorization: Bearer <token>`.
- **Query Tokens Rejected**: The server rejects tokens in URL query strings with HTTP 400.
- **Log Privacy**: Secret tokens are never written to log files or consoles.

## API and Transports

The public API has 53 dotted methods, from `interface.get` to `batch.execute`.

### WebSocket JSON-RPC 2.0

WebSocket sends strict JSON-RPC 2.0 requests with dotted method names:

```json
{"jsonrpc":"2.0","id":"r1","method":"program.get","params":{}}
```

Call `interface.get` to discover all supported methods and schemas.

### Model Context Protocol (MCP)

MCP exposes the same operations, except `interface.get`, through 15 tools over Streamable HTTP:
- `ghidra.help`: Discover domains, list operations, or view schemas.
- 14 Domain Tools: `ghidra.program`, `ghidra.memory`, `ghidra.function`, `ghidra.listing`, etc.

Call an operation with its operation name in the domain tool and its parameters.
For example, the `program.get` method is the `get` operation of `ghidra.program`:

```json
{
  "name": "ghidra.program",
  "arguments": {
    "operation": "get",
    "params": {}
  }
}
```

Each MCP request must also send MCP metadata and headers. See [Protocol Specification](docs/protocol.md).

The MCP tool schema is also available at `ghidra-bridge://contracts/mcp-tools`.

## Documentation Index

- [Overview](docs/overview.md): System concepts, concurrency model, and query patterns.
- [Architecture](docs/architecture.md): Module boundaries and dependency graph.
- [Protocol Specification](docs/protocol.md): JSON-RPC envelopes, MCP endpoints, and error formats.
- [Batch and Transactions](docs/batch-and-transactions.md): Atomic execution and transaction boundaries.
- [Development Guide](docs/development.md): Environment setup, workflows, and quality gates.
- [Method Reference](docs/api.md): Full 53-method catalog and schemas.
- [AsyncAPI Contract](docs/asyncapi.yaml): Formal WebSocket contract.
- [MCP Tools Contract](docs/mcp-tools.json): Formal MCP tool definitions.

## Verify the Build

Run the full verification suite before committing changes:

```bash
./gradlew --no-daemon clean verify
```

The `verify` task checks:
- Architecture boundary rules.
- Generated API contract drift.
- Generated script build and compilation.

The MCP test suite in [tests/](tests/README.md) runs every MCP tool against Ghidra in headless mode.
