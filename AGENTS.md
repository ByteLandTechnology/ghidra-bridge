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
- **Compiler lints**: Java main, test, and script compile tasks target release 21 with `-Xlint:all` and `-Werror`. Change code to fix warnings instead of lint exclusions or SpotBugs, PMD, ErrorProne, or JSR-305 suppressions. Use `@SuppressWarnings` at the narrowest scope only when a JDK API forces a cast or close check.
- **Javadoc checks**: `javadoc` checks all 8 Java subprojects with `-Xdoclint:all` and `-Werror`. Write complete Javadoc comments (`@param`, `@return`, `@throws`, and serialized exception fields) on all public and protected APIs.
- **Zero runtime dependencies**: Keep zero third-party runtime dependencies in `ghidra-bridge.jar`. Keep `org.gradle.dependency.verification=strict` in `gradle.properties`, remove unused checksums from `gradle/verification-metadata.xml`, and do not add third-party static-analysis plugins.
- **Simplified Technical English**: Use ASD-STE100 Simplified Technical English for documentation, code comments, Javadoc comments, and commit messages.

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
- `verifyApiContracts`: Checks that checked-in contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Verifies that no module outside `adapter` and `launcher` imports `ghidra.*`.

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

Check `version.txt`, `.release-please-manifest.json`, and the JAR manifest, then build the release archive and SHA-256 checksum in `build/release/`:

```bash
bash .github/scripts/package-release.sh
```

## Releases

- CI keeps the `verify -> release -> publish` job sequence without cross-job workflow artifacts.
- `release-please` creates a `v<version>` tag and a draft GitHub release (`"draft": true` and `"force-tag-creation": true` in `release-please-config.json`).
- `publish` gets `needs.release.outputs.sha` with `persist-credentials: false` and checks `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft == true`, `.release-please-manifest.json`, and `version.txt`.
- `publish` runs `package-release.sh` (which runs `verify` in CI and `clean verify` locally) and `tests/function_mutation_regression.py` before asset upload.
- `publish` checks non-empty `.zip` and `.sha256` files, verifies `sha256sum -c`, and uploads both assets with `gh release upload --clobber`.
- `publish` makes the draft release public last with `gh api --method PATCH` and `-F draft=false`.
- If `publish` fails, the GitHub release stays hidden as a draft until you rerun the failed jobs.
