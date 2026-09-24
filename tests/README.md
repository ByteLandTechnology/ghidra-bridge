# MCP Tests

This directory holds the test suite for the MCP transport.
The suite loads a sample binary into Ghidra in headless mode and calls every MCP tool through Streamable HTTP.

## Contents

- `sample/`: A small C and C++ program. CMake builds it into the `sample_mixed` test binary.
- `mcp-client/`: A Rust test client. It starts Ghidra, runs the test cases, and stops Ghidra.

## Prerequisites

- Ghidra 12.1 and the Java version that it needs.
- A C and C++ compiler and CMake 3.16 or newer.
- Rust 1.87 or newer with Cargo.
- The bridge scripts. Run `./gradlew buildGhidraScript` in the repository root.

## Run the Tests

Build the sample binary:

```bash
cmake -S tests/sample -B tests/sample/build
cmake --build tests/sample/build
```

Run the test client from the repository root:

```bash
cargo run --release --manifest-path tests/mcp-client/Cargo.toml -- \
  --ghidra-install-dir /path/to/ghidra \
  --script-dir build/ghidra-script \
  --binary tests/sample/build/sample_mixed
```

The client does not search for Ghidra, the scripts, or the binary.
Supply each path as an argument.

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--ghidra-install-dir` | Yes | Ghidra installation directory. It must contain `support/analyzeHeadless`. |
| `--script-dir` | Yes | Directory with `GhidraMcp.java` and `ghidra-bridge.jar`. |
| `--binary` | Yes | Binary to import. Use the sample binary; the cases check its names, types, and calls. |
| `--work-dir` | No | Directory for the Ghidra project and `ghidra.log`. The default is a new temporary directory. |
| `--keep-work-dir` | No | Keep the work directory after a successful run. |
| `--startup-timeout-secs` | No | Time limit for import, analysis, and server startup. The default is 600. |
| `--filter` | No | Run only the cases whose name contains this text. |

The client exits with code `0` when all cases pass, `1` when a case fails, and `2` when it cannot start the test.
After a failure, the client keeps the work directory and prints the last lines of the Ghidra log.

## What the Tests Check

The client starts `analyzeHeadless` with the `GhidraMcp.java` post-script on a free loopback port with a random bearer token.
It waits until `ping` answers, and then runs the cases in this order:

1. **Setup**: Reads `tools/list` and finds the sample functions, globals, and memory blocks by name. No case uses a fixed address.
2. **Protocol**: Tests `server/discover`, `ping`, resources, notifications, HTTP methods, content type, origin checks, bearer authentication, request metadata, and protocol headers.
3. **Tools**: Tests every operation of every domain tool and `ghidra.help`. Mutation cases undo their changes.
4. **Shutdown**: Calls `ghidra.bridge` `shutdown` and checks that Ghidra exits.

Every successful call must pass these checks:
- The request matches the `inputSchema` of the operation.
- The `structuredContent.result` matches the `outputSchema` of the operation.
- The `text` content is the same JSON as `structuredContent`.

The client gets both schemas from `ghidra.help`, because each schema that it returns is a complete document.

At the end, the client compares the operations that passed with the operations in `tools/list`.
The run fails if an operation has no passing call.

## Other Findings

The tests accept this current behavior. Each item may need a change in the bridge:

- Every domain tool has `readOnlyHint: false` and `destructiveHint: true`, also the tools whose operations only read.
- The CORS `Access-Control-Allow-Methods` header includes `GET`, but GET returns `405`.
  `Access-Control-Allow-Headers` does not include `Mcp-Method` and `Mcp-Name`, which every request needs.
- `analysis.start` accepts an unknown analyzer name. The analysis task then ends with status `failed`.
- A global variable or data unit with a structure type reports the string `"null"` as its `value`.

## Add a Test Case

1. Add a function with the signature `fn(&mut TestContext) -> Result<()>` to a file in `mcp-client/src/cases/`.
2. Add it to the `cases()` list in the same file.
3. Use `ctx.ok(tool, operation, params)` for calls that must succeed.
   Use `ctx.fail` or `ctx.fail_with` for calls that must fail.
4. Get addresses from `ctx.entry(name)` or `ctx.fact(key)`. Do not write fixed addresses.
