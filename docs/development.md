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

Before you submit a change, run the verification suite:

```bash
./gradlew --no-daemon clean verify
./gradlew --no-daemon test
bash .github/scripts/verify-repository-hygiene.sh
```

The verification tasks check:
- **Architecture**: `verifyArchitecture` verifies that only adapter and launcher import Ghidra classes.
- **Contract Drift**: `verifyApiContracts` verifies that contracts match code.
- **Script Validation**: `compileGeneratedScripts` verifies that generated scripts compile.
- **Distribution**: `verifyDistribution` verifies the contents of `build/ghidra-script/`.
- **Unit Tests**: `test` runs all JUnit test classes across the Gradle modules.

## Releases

The CI workflow uses release-please to manage versions and release notes.
On each push to `main`, the `release` job runs first in a dedicated concurrency group.
For feature commits on `main`, release-please creates or updates the release pull request.
The pull request updates `version.txt`, `.release-please-manifest.json`, and `CHANGELOG.md`.
Review the proposed version and notes in the pull request.
Merge the pull request into `main` to start the release.

When you merge the release pull request, `release` creates a `v<version>` tag and a draft GitHub Release.
Next, `verify` fetches the release commit SHA, runs all verification and test suites, builds the archive, and uploads workflow artifacts.
The `publish` job reuses those verified workflow artifacts without a second Java or Ghidra build.
It verifies the commit SHA, the `v<version>` tag, the draft status, `.release-please-manifest.json`, `version.txt`, and the SHA-256 checksum.
Then `publish` uploads two assets to the draft release and sets `draft=false`:

- `ghidra-bridge-<version>.zip`: Contains `Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`,
  `LICENSE`, and `README.md`.
- `ghidra-bridge-<version>.zip.sha256`: The SHA-256 checksum of the archive.

release-please reads Conventional Commit messages to select the version:

- `fix`: Increases the patch version, such as `1.2.1`.
- `feat`: Increases the minor version, such as `1.3.0`.
- A `!` after the type or a `BREAKING CHANGE:` footer: Increases the major version.
- Other types, such as `docs`, `ci`, and `test`: Do not start a release on their own.

Gradle reads the version from `version.txt` unless you set the `releaseVersion` property.
The package script checks that the release version matches `version.txt`, `.release-please-manifest.json`, and the JAR manifest.
It reuses a verified build when `build/ghidra-script/` matches the target version, or runs `clean verify test` first.
To build and verify the release archive locally, run:

```bash
bash .github/scripts/package-release.sh
```

In Settings > Actions > General, enable "Allow GitHub Actions to create and approve pull requests".
The workflow uses `GITHUB_TOKEN` by default.
Pull requests created with this token do not start CI without a new event.
For CI on release pull requests, set the `RELEASE_PLEASE_TOKEN` secret to a personal access token.
Give that token Contents, Issues, and Pull requests write access to this repository.
See the [release-please Action documentation](https://github.com/googleapis/release-please-action).

If `verify` or `publish` fails, the GitHub Release stays hidden as a draft while `Latest` points to the previous public release.
Select "Re-run failed jobs" in GitHub Actions to recover.
`verify` overwrites the workflow artifacts, and `publish` replaces partial draft assets with `--clobber` before it makes the release public.
