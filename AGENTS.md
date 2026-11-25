# Agent Guidelines

This document defines the build environment, repository rules, and local verification commands for coding agents and contributors in Ghidra Bridge.

## Environment Setup

- **JDK**: Use Java 21 (JDK 21).
- **Ghidra**: Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- **`GHIDRA_INSTALL_DIR`**: Set `GHIDRA_INSTALL_DIR` to the local Ghidra installation directory (or pass `-PghidraInstallDir=/path/to/ghidra`). Gradle requires a resolved Ghidra installation to compile `:adapter`, `:launcher`, and generated scripts, and to run `:adapter` unit tests and headless regression tests.
- **Gradle Wrapper**: Always invoke `./gradlew` from the repository root rather than a system Gradle binary.

## Module Layout and Guardrails

The build defines 8 Java subprojects under `modules/`:
- `:domain` (`modules/domain`)
- `:wire` (`modules/wire`)
- `:contracts` (`modules/contracts`)
- `:runtime` (`modules/runtime`)
- `:adapter` (`modules/adapter`)
- `:launcher` (`modules/launcher`)
- `:transport:websocket` (`modules/transport/websocket`)
- `:transport:mcp` (`modules/transport/mcp`)

Follow these repository rules when you change code:
- **Ghidra API boundary**: Only `modules/adapter` and `modules/launcher` can import `ghidra.*` packages (`verifyArchitecture` enforces this rule).
- **Generated contracts**: Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand. Run `./gradlew generateApiContracts` after public interface changes.
- **Repository hygiene**: Do not commit build directories, IDE files, generated launcher scripts (`Bridge.java`, `GhidraMcp.java`), zero-byte files, or duplicate tracked files.

## Verification Commands

### Module Checks and Unit Tests (`check`)

Run JUnit Platform test suites and module checks across all 8 Java subprojects:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon check
```

To run JUnit tests for a single subproject during iteration:

```bash
./gradlew --no-daemon :domain:test
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test
```

### Full Build and Verification (`clean verify`)

Run the full local Gradle verification check. CI runs `./gradlew --no-daemon verify` on a new checkout for pull requests and release archives. Keep `clean verify` locally to delete previous build output:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `check`: JUnit tests and checks across all 8 Java subprojects.
- `verifyApiContracts`: Checks that checked-in contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Verifies that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Test Timeouts, Debugging, and Failure Reports

Every Gradle `Test` task enforces:
- A **5-minute** Gradle task timeout (`Duration.ofMinutes(5)`).
- **30-second** cooperative (`SAME_THREAD`) JUnit Jupiter timeouts for test and lifecycle methods (`junit.jupiter.execution.timeout.default=30s`, `junit.jupiter.execution.timeout.testable.method.default=30s`, `junit.jupiter.execution.timeout.lifecycle.method.default=30s`) with live thread dumps (`junit.jupiter.execution.timeout.threaddump.enabled=true`).
- `FULL` exception formatting with causes and stack traces, printing buffered standard streams (`stdout` and `stderr`) only for failed tests.

`junit.jupiter.execution.timeout.mode` defaults to `disabled_on_debug`, so attaching a debugger automatically disables JUnit timeouts:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test --debug-jvm
```

To disable JUnit timeouts explicitly without attaching a debugger:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon -Djunit.jupiter.execution.timeout.mode=disabled :adapter:test
```

Failure diagnostics and reports are written to:
- JUnit XML reports: `modules/**/build/test-results/test/TEST-*.xml`
- JUnit HTML reports: `modules/**/build/reports/tests/test/index.html`
- Headless regression failure log: `build/reports/headless-regression/headless.log` (printed to `stderr` and archived on failure; uploaded in CI as `verify-test-diagnostics` and `publish-test-diagnostics`)

### Repository Hygiene Check

Check tracked files for build artifacts, stale paths, zero-byte files, duplicate files, and API method counts:

```bash
bash .github/scripts/verify-repository-hygiene.sh
```

### Headless Regression Tests

After `buildGhidraScript`, `verify`, or `clean verify` populates `build/ghidra-script/`, run the headless Ghidra function-mutation regression test on Linux x86-64 (requires `gcc` and `nm`):

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Exact Local CI Sequence

Run these three commands in order to match the `verify` job in `.github/workflows/ci.yml`. CI runs `./gradlew --no-daemon verify` on a new checkout, and local runs use `clean verify` as documented in `CONTRIBUTING.md`:

```bash
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Release Archive Check

Check `version.txt`, `.release-please-manifest.json`, and the JAR manifest, run Gradle verification with `--stacktrace`, and build the release archive and SHA-256 checksum in `build/release/`:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra bash .github/scripts/package-release.sh
```

## Releases

- CI keeps the `verify -> release -> publish` job sequence without cross-job workflow artifacts.
- `release-please` creates a `v<version>` tag and a draft GitHub release (`"draft": true` and `"force-tag-creation": true` in `release-please-config.json`).
- `publish` gets `needs.release.outputs.sha` with `persist-credentials: false` and checks `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft == true`, `.release-please-manifest.json`, and `version.txt`.
- `publish` runs `package-release.sh` (which runs `verify` in CI and `clean verify` locally) and `tests/function_mutation_regression.py` before asset upload.
- `publish` checks non-empty `.zip` and `.sha256` files, verifies `sha256sum -c`, and uploads both assets with `gh release upload --clobber`.
- `publish` makes the draft release public last with `gh api --method PATCH` and `-F draft=false`.
- If `publish` fails, the GitHub release stays hidden as a draft until you rerun the failed jobs.
