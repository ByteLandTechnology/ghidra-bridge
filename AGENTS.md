# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Environment Setup

- **JDK**: Use Java 21 (JDK 21).
- **Ghidra**: Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- **`GHIDRA_INSTALL_DIR`**: Set `GHIDRA_INSTALL_DIR` to the local Ghidra installation directory, or pass `-PghidraInstallDir=/path/to/ghidra`. Gradle needs Ghidra to compile `:adapter`, `:launcher`, and generated scripts, and to run `:adapter` and headless tests.
- **Gradle Wrapper**: Always run `./gradlew` from the repository root instead of a system Gradle binary.

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
- **Repository hygiene**: Do not commit build directories, IDE files, generated scripts (`Bridge.java`, `GhidraMcp.java`), zero-byte files, or duplicate tracked files.
- **Compiler lints**: Java main, test, and script compile tasks target release 21 with `-Xlint:all` and `-Werror`. Change code to fix warnings instead of lint exclusions or SpotBugs, PMD, ErrorProne, or JSR-305 suppressions. Use `@SuppressWarnings` at the narrowest scope only when a JDK API forces a cast or close check.
- **Javadoc checks**: `javadoc` checks all 8 Java subprojects with `-Xdoclint:all` and `-Werror`. Write complete Javadoc comments (`@param`, `@return`, `@throws`, and serialized exception fields) on all public and protected APIs.
- **Zero runtime dependencies**: Keep zero third-party runtime dependencies in `ghidra-bridge.jar`. Keep `org.gradle.dependency.verification=strict` in `gradle.properties`, remove unused checksums from `gradle/verification-metadata.xml`, and do not add third-party static-analysis plugins.

## GitHub Actions

- Pin each external `uses:` step in `.github/workflows/` and `.github/actions/` to a 40-character commit SHA.
- Add a `# vX.Y.Z` version comment after each commit SHA, such as `# v4.4.0`.
- Do not use mutable tags or branch names such as `@v4` or `@main`.
- Keep local composite action paths that start with `./`, such as `./.github/actions/setup-ghidra`.
- Keep weekly `github-actions` updates in `.github/dependabot.yml` for `/` and `/.github/actions/setup-ghidra`.
- Do not add a `gradle` ecosystem to `.github/dependabot.yml` so `gradle/verification-metadata.xml` stays intact.

## Commit Messages

- Obey Conventional Commits, such as `fix(wire): reject unknown fields`.
- Use no more than 72 characters on each line, with spaces and list markers counted.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters, with no period at the end.
- Do not add attribution lines to commit messages or pull request text.

## Verification Commands

### Workflow, Shell, and Hygiene Checks

Check GitHub Actions workflows, shell scripts, tracked files, duplicates, API method counts, SHA-pinned GitHub Actions, URLs, and MCP tool names:

```bash
actionlint
shellcheck .github/scripts/*.sh
bash .github/scripts/verify-repository-hygiene.sh
```

### Architecture Check (`verifyArchitecture`)

Check module import boundaries without a Ghidra installation:

```bash
./gradlew --no-daemon verifyArchitecture
```

### Module Checks and Unit Tests (`check`)

Run JUnit Platform test suites and module checks across all 8 Java subprojects:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon check
```

To run JUnit tests for one subproject during iteration:

```bash
./gradlew --no-daemon :domain:test
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test
```

### Compiler Lints and Javadoc Checks

Compile main, test, and generated script classes with Java 21 lints, and check Javadoc comments across all 8 Java subprojects:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon classes testClasses compileGeneratedScripts
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon javadoc
```

### Full Build and Verification (`clean verify`)

Run the full local Gradle verification check. CI runs `./gradlew --no-daemon verify` on a new checkout for pull requests and release archives. Keep `clean verify` locally to delete previous build output:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `check`: JUnit tests and checks across all 8 Java subprojects.
- `testClasses`: Test compilation with Java 21 `-Xlint:all` and `-Werror` across all 8 Java subprojects.
- `javadoc`: Javadoc validation with `-Xdoclint:all` and `-Werror` across all 8 Java subprojects.
- `verifyApiContracts`: Checks that tracked contracts match generated output.
- `verifyMcpDocumentation`: Checks MCP tool contract rules and MCP documentation consistency.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Checks that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Test Timeouts, Debugging, and Failure Reports

Every Gradle `Test` task sets:
- A **5-minute** Gradle task timeout (`Duration.ofMinutes(5)`).
- **30-second** cooperative (`SAME_THREAD`) JUnit Jupiter timeouts for test and lifecycle methods (`junit.jupiter.execution.timeout.default=30s`, `junit.jupiter.execution.timeout.testable.method.default=30s`, `junit.jupiter.execution.timeout.lifecycle.method.default=30s`) with thread dumps (`junit.jupiter.execution.timeout.threaddump.enabled=true`).
- `FULL` exception output with causes and stack traces. Gradle prints buffered `stdout` and `stderr` streams only when a test fails.

`junit.jupiter.execution.timeout.mode` defaults to `disabled_on_debug`. Attach a debugger to disable JUnit timeouts:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test --debug-jvm
```

To disable JUnit timeouts without a debugger:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon -Djunit.jupiter.execution.timeout.mode=disabled :adapter:test
```

Test runs write failure reports to:
- JUnit XML reports: `modules/**/build/test-results/test/TEST-*.xml`
- JUnit HTML reports: `modules/**/build/reports/tests/test/index.html`
- Headless regression failure log: `build/reports/headless-regression/headless.log` (printed to `stderr` and saved on failure; uploaded in CI as `verify-test-diagnostics` and `publish-test-diagnostics`)

### Headless Regression Tests

Run the headless function-mutation regression test on Linux x86-64 after `buildGhidraScript`, `verify`, or `clean verify`. This test needs `gcc` and `nm`:

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Exact Local CI Sequence

Run these six commands in order to match the `lint` and `verify` jobs in `.github/workflows/ci.yml`. CI runs `./gradlew --no-daemon verify` on a new checkout, and local runs use `clean verify` as documented in `CONTRIBUTING.md`:

```bash
actionlint
shellcheck .github/scripts/*.sh
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
python3 tests/release_archive_reproducibility.py
```

### Release Archives and Provenance

Check `version.txt`, `.release-please-manifest.json`, and the JAR manifest, run Gradle verification with `--stacktrace`, and build the deterministic release archive and SHA-256 checksum in `build/release/`. Run `tests/release_archive_reproducibility.py` to test archive reproducibility across delayed runs:

```bash
bash .github/scripts/package-release.sh
python3 tests/release_archive_reproducibility.py
```

Verify a downloaded release archive with `sha256sum` and GitHub CLI provenance verification:

```bash
sha256sum -c ghidra-bridge-<version>.zip.sha256
gh attestation verify ghidra-bridge-<version>.zip --repo ByteLandTechnology/ghidra-bridge
```

## Releases

- CI keeps the `[lint, verify] -> release -> publish` job sequence without cross-job workflow artifacts.
- `release-please` creates a `v<version>` tag and a draft GitHub release (`"draft": true` and `"force-tag-creation": true` in `release-please-config.json`).
- `publish` gets `needs.release.outputs.sha` with `persist-credentials: false` and checks `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft == true`, `.release-please-manifest.json`, and `version.txt`.
- `publish` runs `package-release.sh` (which runs `verify` in CI and `clean verify` locally) and `tests/function_mutation_regression.py` before asset upload.
- `publish` signs SLSA build provenance with `actions/attest-build-provenance` (`id-token: write` and `attestations: write`) before asset upload.
- `publish` checks non-empty `.zip` and `.sha256` files, verifies `sha256sum -c`, and uploads both assets with `gh release upload --clobber`.
- `publish` makes the draft release public last with `gh api --method PATCH` and `-F draft=false`.
- If `publish` fails, the GitHub release stays hidden as a draft until you rerun the failed jobs.
