# Development Guide

This guide describes how to build, extend, and verify the Ghidra Bridge codebase.

## Prerequisites

- **Java Development Kit**: Use JDK 21.
- **Ghidra**: Use Ghidra 12.1 or newer to compile adapters.
- **Environment**: Set `GHIDRA_INSTALL_DIR` to the Ghidra installation path.

Gradle resolves Ghidra from:
1. The `-PghidraInstallDir` command line property.
2. The `GHIDRA_INSTALL_DIR` environment variable.
3. The `ghidraRun` executable on your system `PATH`.
4. Homebrew installations of Ghidra.
5. The `analyzeHeadless` executable on your system `PATH`.
6. Standard installation directories on your machine.

## Use Gradle

Always use the Gradle Wrapper in this repository:

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
Use `GhidraSession` to manage transactions for mutation operations.

### Step 3: Register the Method in Wire

Register the new operation in `modules/wire` with `ApiRegistry`:
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

Do not edit these files by hand.
The build fails if repository files differ from the generator output.

To test function mutations in an isolated Ghidra project on Linux x86-64, run:

```bash
./gradlew buildGhidraScript
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

The test requires `gcc` and `nm`.

## Quality Checks

Before you submit a change, run the local lint, hygiene, and verification checks:

```bash
actionlint
shellcheck .github/scripts/*.sh
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
```

On Linux x86-64, CI also runs `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"` after `clean verify`.

To check module import boundaries without a Ghidra installation, run:

```bash
./gradlew --no-daemon verifyArchitecture
```

The verification checks enforce these rules:
- **Workflows and Shell Scripts**: `actionlint` and `shellcheck` validate GitHub Actions workflows, composite actions, and shell scripts.
- **Repository Hygiene**: `verify-repository-hygiene.sh` checks tracked files, duplicates, URLs, and MCP tool names.
- **Unit Tests**: `check` runs JUnit tests across all Java modules.
- **Architecture**: `verifyArchitecture` verifies that only adapter and launcher import Ghidra classes.
- **Contract Drift**: `verifyApiContracts` verifies that contracts match code.
- **Script Validation**: `compileGeneratedScripts` verifies that generated scripts compile.
- **Distribution**: `verifyDistribution` verifies the contents of `build/ghidra-script/`.

## Releases

The CI workflow uses release-please to manage versions and release notes.
After a push to `main` passes the `verify` job, release-please creates or updates a release pull request.
The pull request updates `version.txt`, `.release-please-manifest.json`, and `CHANGELOG.md`.
Review the proposed version and notes in the pull request.
Merge the pull request into `main` to start the release.
After verification, release-please creates a `v<version>` tag and a draft GitHub release.

release-please reads Conventional Commit messages to select the version:

- `fix`: Increases the patch version, such as `1.2.1`.
- `feat`: Increases the minor version, such as `1.3.0`.
- A `!` after the type or a `BREAKING CHANGE:` footer: Increases the major version.
- Other types, such as `docs`, `ci`, and `test`: Do not start a release on their own.

The `publish` job gets the release commit without persisted credentials.
Before Gradle runs, it checks `HEAD`, the `v<version>` tag, the remote tag SHA, the draft state,
`.release-please-manifest.json`, and `version.txt`.
Next, it builds the release archive with `verify` (which runs all JUnit tests) and runs `tests/function_mutation_regression.py`.
Then it verifies non-empty files and the SHA-256 checksum, uploads two assets, and makes the draft release public:

- `ghidra-bridge-<version>.zip`: Contains `Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`,
  `LICENSE`, and `README.md`.
- `ghidra-bridge-<version>.zip.sha256`: The SHA-256 checksum of the archive.

Gradle reads the version from `version.txt` unless you set the `releaseVersion` property.
The package script checks that the release version matches `version.txt`, `.release-please-manifest.json`,
and the JAR manifest.
To build and verify the release archive locally, run:

```bash
bash .github/scripts/package-release.sh
```

In Settings > Actions > General, enable "Allow GitHub Actions to create and approve pull requests".
The workflow uses `GITHUB_TOKEN` by default.
Pull requests created with this token do not start CI without a new event.
For CI on release pull requests, close and reopen the pull request, or set the `RELEASE_PLEASE_TOKEN` secret to a personal access token.
Give that token Contents and Pull requests write access to this repository.
See the [release-please Action documentation](https://github.com/googleapis/release-please-action).

If the `publish` job fails, the GitHub release stays hidden as a draft.
Select "Re-run failed jobs" in GitHub Actions to repeat the checks, replace uploaded assets, and publish the draft.
