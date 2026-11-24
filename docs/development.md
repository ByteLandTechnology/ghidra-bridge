# Development Guide

This guide describes how to build, extend, and verify the Ghidra Bridge codebase.

## Prerequisites

- **Java Development Kit**: Use JDK 21.
- **Ghidra**: Use Ghidra 12.1 or newer to compile adapters.
- **Environment**: Set `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME` to the Ghidra installation path.
- **Windows Git Configuration**: Run `git config --global core.autocrlf false` before checkout so generated LF contracts do not drift.

Gradle resolves Ghidra from:
1. The `-PghidraInstallDir` command-line property.
2. The `GHIDRA_INSTALL_DIR` environment variable.
3. The `GHIDRA_HOME` environment variable.
4. The `analyzeHeadless` (`analyzeHeadless.bat` on Windows) executable on `PATH`.
5. The `ghidraRun` (`ghidraRun.bat` on Windows) executable on `PATH`.
6. Homebrew installations of Ghidra (newest version first).
7. Standard installation directories on Linux, macOS (`Ghidra.app` bundles and `/Applications`), and Windows (`Program Files`, `LOCALAPPDATA`, Scoop, Chocolatey, and system drive), newest version first.

## Use Gradle

Always use the Gradle Wrapper in this repository (`./gradlew` on Linux and macOS, `.\gradlew.bat` on Windows):

```bash
# Run fast checks without a local Ghidra installation
./gradlew --no-daemon verifyArchitecture verifyGhidraDetection
./gradlew --no-daemon :wire:test :contracts:test

# Verify synthetic Ghidra path detection across Linux, macOS, and Windows layouts
./gradlew --no-daemon verifyGhidraDetection

# Build the user distribution
./gradlew buildGhidraScript

# Run full verification against Ghidra 12.1.4 and the Ghidra 12.1.2 floor release
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC ./gradlew --no-daemon clean verify
GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC ./gradlew --no-daemon clean verify
```

On Windows PowerShell or Command Prompt:

```powershell
.\gradlew.bat --no-daemon verifyGhidraDetection
.\gradlew.bat -PghidraInstallDir=C:\ghidra_12.1.4_PUBLIC --no-daemon clean verify
.\gradlew.bat --no-daemon :wire:test :contracts:test
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

To test function mutations in an isolated headless Ghidra project on Linux, macOS, or Windows, run:

```bash
./gradlew buildGhidraScript
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
python3 tests/function_mutation_regression.py --arch aarch64 "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

On Windows:

```powershell
.\gradlew.bat buildGhidraScript
python tests/function_mutation_regression.py "%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat"
```

The script writes x86-64 and AArch64 ELF test binaries in Python and needs no external compiler.

## Quality Checks

Before you submit a change, run the verification suite:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

The verification tasks check:
- **Architecture**: `verifyArchitecture` verifies that only adapter and launcher import Ghidra classes.
- **Ghidra Detection**: `verifyGhidraDetection` verifies synthetic `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `Ghidra.app`, version order, and Windows folder layouts.
- **Contract Drift**: `verifyApiContracts` verifies that contracts match code.
- **Script Validation**: `compileGeneratedScripts` verifies that generated scripts compile.
- **Distribution**: `verifyDistribution` verifies the contents of `build/ghidra-script/`.

## Releases

The CI workflow uses release-please to manage versions and release notes.
After a push to `main` passes the `verify` job, release-please creates or updates a release pull request.
The pull request updates `version.txt`, `.release-please-manifest.json`, and `CHANGELOG.md`.
Review the proposed version and notes in the pull request.
Merge the pull request into `main` to start the release.
After verification, release-please creates a `v<version>` tag and a GitHub release.

release-please reads Conventional Commit messages to select the version:

- `fix`: Increases the patch version, such as `1.2.1`.
- `feat`: Increases the minor version, such as `1.3.0`.
- A `!` after the type or a `BREAKING CHANGE:` footer: Increases the major version.
- Other types, such as `docs`, `ci`, and `test`: Do not start a release on their own.

The `publish` job gets the release commit and verifies the build.
Then it uploads two assets:

- `ghidra-bridge-<version>.zip`: Contains `Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`,
  `LICENSE`, and `README.md`.
- `ghidra-bridge-<version>.zip.sha256`: The SHA-256 checksum of the archive.

Gradle reads the version from `version.txt` unless you set the `releaseVersion` property.
The package script checks that the release version matches `version.txt` and the JAR manifest.
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

If the `publish` job fails, use "Re-run failed jobs" in GitHub Actions.
The upload step can replace assets from an earlier attempt that did not complete.
