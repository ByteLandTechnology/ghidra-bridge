# Architecture

Ghidra Bridge uses a modular architecture with strict one-way dependencies.
All source modules are in the `modules/` directory.

## Dependency Graph

```text
modules/domain (Service interfaces and data models)
       ▲
       └── modules/wire (Method registry and JSON codecs)
                 ▲
                 └── modules/runtime (Dispatcher and session control)
                           ▲
                           ├── modules/transport/websocket (WebSocket JSON-RPC)
                           ├── modules/transport/mcp (MCP Streamable HTTP)
                           └── modules/adapter (Ghidra service implementations)
                                     ▲
                                     └── modules/launcher (Bootstrap and scripts)
```

The adapter module also depends directly on `modules/domain` and `modules/wire`.
The launcher module depends on the adapter and on both transport modules.

The architecture separates domain logic, wire protocols, and Ghidra APIs.

## Module Responsibilities

### 1. `modules/domain`

The domain module defines the core service interfaces and data transfer models:
- Service interfaces include `ProgramService`, `MemoryService`, `ListingService`, `FunctionService`, and `DataTypeService`.
- Model records include `AddressResource`, `InstructionResource`, `FunctionResource`, and `Page`.
- It defines domain exceptions such as `DomainException`, `GlobalVariableConflictException`, and `TransactionExecutionException`.
- **Constraint**: This module must not import any Ghidra API classes.

### 2. `modules/wire`

The wire module maintains the unified method catalog:
- `ApiRegistry` defines all 55 public dotted methods and their input and output schemas.
- `JsonParser`, `JsonWriter`, and `JsonUtil` parse and format JSON.
- `ApiContractGenerator` generates `docs/api.md`, `docs/asyncapi.yaml`, and `docs/mcp-tools.json`.
- **Constraint**: Untyped JSON values stop at this boundary.

### 3. `modules/runtime`

The runtime module manages request execution and session lifecycle:
- `AgentDispatcher` dispatches each request to the target method handler.
- It runs one request at a time. `DispatchBarrier` tracks in-flight requests and rejects new requests during shutdown.
- It maintains session state and coordinates graceful shutdown.
- **Constraint**: This module has no dependency on Ghidra classes.

### 4. `modules/adapter`

The adapter module connects domain service interfaces to Ghidra:
- `GhidraSession` manages active program references and transaction lifecycles.
- Service implementations translate domain operations into Ghidra API calls.
- `GhidraServiceFactory` creates all service implementations.
- **Constraint**: Only this module and the launcher can import Ghidra packages.

### 5. `modules/transport/websocket`

This module implements the WebSocket transport:
- `AgentWebSocketServer` implements an embedded WebSocket server.
- `AgentClient` runs the WebSocket transport as an embedded server or as an outbound client to `ws_url`.
- `MessageEnvelope` validates JSON-RPC 2.0 requests, responses, and error envelopes.

### 6. `modules/transport/mcp`

This module implements the Model Context Protocol:
- `McpHttpServer` implements a Streamable HTTP server that complies with protocol `2026-07-28`.
- `McpToolRegistry` maps 54 public methods to 14 domain tools and `ghidra.help`.
  It does not publish `interface.get`.
- It serves the contract resource at `ghidra-bridge://contracts/mcp-tools`.

### 7. `modules/launcher`

The launcher module starts the bridge and generates Ghidra scripts:
- `Bootstrap` reads launch arguments and starts the selected transport.
- The build generates `Bridge.java` and `GhidraMcp.java` from `GhidraLauncher.java.template`.
- It packages the runtime classes in `ghidra-bridge.jar`.
- In outbound mode, the session ends when the connection closes or the host process stops.
  The JDK WebSocket does not always report a connection that the host closed.
  Thus, the client sends a keepalive ping every 5 seconds.
  A ping failure ends the session.
  Then the bridge cancels an active analysis and saves the program.
  The script returns, and a headless Ghidra exits.

  The `exit_deadline_sec` value sets an exit time limit.
  `GracefulExit` halts the JVM if Ghidra does not exit before this limit.
  A save operation that is active at the limit completes first.
  The host does not need a separate watchdog process.

## Architecture Rules and Enforcement

The project uses these checks for architectural boundaries:
- The `verifyArchitecture` Gradle task checks package imports across all modules.
- Only `modules/adapter` and `modules/launcher` can import packages whose names start with `ghidra.`.
- The `verifyApiContracts` task generates contracts in a build sandbox and fails on a difference.
- Run `./gradlew clean verify` to check these rules.
