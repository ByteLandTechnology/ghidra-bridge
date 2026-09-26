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

## Releases

The CI workflow publishes releases with semantic-release.
A release starts only after a push to `main` passes the `verify` job.

semantic-release reads the Conventional Commit messages since the last `v*` tag:
- `fix`: Publishes a patch release, such as `0.3.1`.
- `feat`: Publishes a minor release, such as `0.4.0`.
- A `!` after the type or a `BREAKING CHANGE:` footer: Publishes a major release.
- Other types, such as `docs`, `ci`, and `test`: Do not publish a release.

Each release creates a `v<version>` tag and a GitHub release with generated notes.
The release has two assets:
- `ghidra-bridge-<version>.zip`: `Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`, `LICENSE`, and `README.md`.
- `ghidra-bridge-<version>.zip.sha256`: The SHA-256 checksum of the archive.

The release does not commit files to the repository.
The build gets the version from the `releaseVersion` Gradle property.
Local builds use the version `0.0.0-dev`.

To build a release archive locally, run:

```bash
bash .github/scripts/package-release.sh 0.3.0
```

To preview the next version without a release, run:

```bash
npm ci
npx semantic-release --dry-run --no-ci
```
