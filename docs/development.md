# Development Guide

This guide describes how to build, extend, and verify the Ghidra Bridge codebase.

## Prerequisites

- **Java Development Kit**: JDK 21 is required.
- **Ghidra**: Ghidra 12.1 or newer is required to compile adapters and run the MCP tests.
- **Environment**: Set `GHIDRA_INSTALL_DIR` to the Ghidra installation path.

Gradle resolves Ghidra from:
1. The `-PghidraInstallDir` command line property.
2. The `GHIDRA_INSTALL_DIR` environment variable.
3. The `ghidraRun` executable on your system `PATH`.
4. Homebrew installations of Ghidra.
5. The `analyzeHeadless` executable on your system `PATH`.
6. Standard installation directories on your machine.

## Working with Gradle

Always use the checked-in Gradle Wrapper:

```bash
# Build the user distribution
./gradlew buildGhidraScript

# Run all verification checks
./gradlew --no-daemon clean verify
```

The `buildGhidraScript` task creates three files in `build/ghidra-script/`:
- `Bridge.java`
- `GhidraMcp.java`
- `ghidra-bridge.jar`

## How to Add or Change an API Operation

Follow this sequence to modify the public interface:

### Step 1: Update the Domain Model

Define the service method and data types in `modules/domain`.
Keep domain interfaces independent of Ghidra APIs.

### Step 2: Implement the Ghidra Adapter

Implement the service method in `modules/adapter`.
Convert Ghidra data structures into typed domain records.
Use `GhidraSession` to manage transactions for mutating operations.

### Step 3: Register the Method in Wire

Register the new operation in `modules/wire` using `ApiRegistry`:
- Assign a public dotted name, such as `program.get`.
- Define the input and output schemas.
- Connect the handler to the domain service interface.

### Step 4: Regenerate Public Contracts

Run the contract generator task:

```bash
./gradlew generateApiContracts
```

This task regenerates:
- `docs/api.md`
- `docs/asyncapi.yaml`
- `docs/mcp-tools.json`

Do not edit these files manually.
The build fails if checked-in files differ from the generator output.

## Quality Gates

Before submitting a change, run the verification suite:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

The verification tasks check:
- **Architecture**: `verifyArchitecture` verifies that only adapter and launcher import Ghidra classes.
- **Contract Drift**: `verifyApiContracts` verifies that contracts match code.
- **Script Validation**: `compileGeneratedScripts` verifies that generated scripts compile.
- **Distribution**: `verifyDistribution` verifies the contents of `build/ghidra-script/`.

## MCP Tests

The `tests/` directory holds an MCP test suite.
It runs every MCP tool against a sample C/C++ binary in Ghidra headless mode.
See [tests/README.md](../tests/README.md) for instructions.
