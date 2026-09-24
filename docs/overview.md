# Overview

Ghidra Bridge gives network access to one active Ghidra program.
The bridge supports two network transports: WebSocket JSON-RPC 2.0 and MCP Streamable HTTP `2026-07-28`.
The registry defines 53 public dotted methods, from `interface.get` to `batch.execute`.
WebSocket publishes all 53 methods. MCP publishes 52 methods; `interface.get` is WebSocket only.
The runtime JAR has zero third-party dependencies.

## Design Goals

- **Single Catalog**: All operations, schemas, and handlers live in one typed method registry.
- **Transport Parity**: WebSocket and MCP share identical parameters, return values, errors, and validation rules.
- **No Third-Party Dependencies**: The core runtime and transports use standard Java 21 platform libraries.
- **Strict Isolation**: Ghidra API classes stay behind service interfaces in the adapter module.

## Concurrency and Session Model

The bridge binds to one active Ghidra program per session.
Requests run sequentially in a single dispatch queue.
The dispatcher executes only one operation at a time.

Ghidra background analysis runs in a separate thread.
While analysis runs:
- Read operations remain available.
- Mutation operations return an error with HTTP status `409` and code `analysis_in_progress`.
- Starting another analysis returns status `409` and code `analysis_already_running`.

## Common Request Patterns

Methods follow standard resource patterns across both transports:

- **Get and Delete**: Requests supply a `selector` object, such as an address or identifier.
- **Update**: Requests supply a `selector` object and a `patch` object with modified fields.
- **Create**: Requests supply a `resource` object with the initial attributes.
- **List**: Requests accept an optional `filter` object and an optional `page` object with a `limit` integer and an opaque `cursor` string.
- **Field Projection**: List and get operations accept an optional `projection.fields` array to select output properties.

## Bounded Address Scans

Address-ordered scan operations inspect memory items cooperatively.
Applicable listing operations include:
- `code_unit.list`.
- `data_unit.list`.
- `instruction.list`.
- `function.list`.
- `global_variable.list`.
- `symbol.list`.
- `comment.list`.
- `flow_override.list`.

Scan operations accept a `scan` object.
The `scan.range` object supplies `start` and `end` addresses.
The `scan.timeout_ms` limit is between 100 and 60000 milliseconds.
The default timeout is 1000 milliseconds.

The response object includes a `scan` metadata block:

```json
{
  "items": [],
  "next_cursor": "eyJ...",
  "scan": {
    "kind": "address",
    "requested_start": "ram:00100000",
    "requested_end": "ram:001fffff",
    "scanned_start": "ram:00100000",
    "scanned_end": "ram:0017ffff",
    "complete": false,
    "stop_reason": "timeout",
    "elapsed_ms": 1000
  }
}
```

The `stop_reason` property reports `completed`, `limit`, or `timeout`.
An incomplete scan returns a `next_cursor` value even when zero items match.
The caller passes this value as `page.cursor` to continue the scan from the last visited location.

## Global Variables and Data Coordination

The `global_variable` methods coordinate defined data items and primary labels.
Creating or upserting a variable requires an address, a name, and a structured data-type reference.
Mutations do not overwrite instructions or unrelated data items.
Deleting a global variable clears the data definition and preserves the label unless requested.

## Next Steps

- Consult the [Architecture Guide](architecture.md) for module decomposition.
- Read the [Protocol Specification](protocol.md) for envelope details and error formats.
- Review [Batch and Transactions](batch-and-transactions.md) for atomic execution semantics.
- See the [Method Reference](api.md) for the complete list of 53 methods.
