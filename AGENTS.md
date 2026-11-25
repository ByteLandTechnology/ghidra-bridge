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

Run compiler lints, ErrorProne, SpotBugs, Javadoc checks, and JUnit Platform test suites across all 8 Java subprojects:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon check
```

Run individual static analysis, Javadoc, or unit test gates during iteration:

```bash
# Compiler lints (-Xlint:all,-path -Werror) and ErrorProne on main, test, and generated scripts
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon compileJava compileTestJava compileGeneratedScripts

# SpotBugs bytecode analysis (exclusions in gradle/spotbugs-exclude.xml)
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon spotbugsMain spotbugsTest

# Strict Javadoc validation (-Xdoclint:all -Werror)
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon javadoc

# Single-module JUnit tests
./gradlew --no-daemon :domain:test
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test
```

### Dependency Verification Checksums

`gradle.properties` sets `org.gradle.dependency.verification=strict` and checks every plugin and dependency artifact against `gradle/verification-metadata.xml`. When you add or upgrade a Gradle plugin or dependency, regenerate SHA-256 checksums from an empty `GRADLE_USER_HOME`:

```bash
cold_gradle_home="$(mktemp -d)"
GRADLE_USER_HOME="$cold_gradle_home" GHIDRA_INSTALL_DIR=/path/to/ghidra \
  ./gradlew --no-daemon --write-verification-metadata sha256 clean verify
rm -rf "$cold_gradle_home"
```

### Full Build and Verification (`clean verify`)

Run the full Gradle verification gate used in pull requests and release archives:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `check`: Java 21 compiler lints (`-Xlint:all,-path` and `-Werror`), ErrorProne, SpotBugs (`spotbugsMain` and `spotbugsTest`), strict Javadoc (`-Xdoclint:all` and `-Werror`), and JUnit tests across all 8 Java subprojects.
- `verifyApiContracts`: Checks that checked-in contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra with compiler lints and ErrorProne (`compileGeneratedScripts`).
- `verifyArchitecture`: Verifies that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Repository Hygiene Check

Check tracked files for build artifacts, stale paths, zero-byte files, duplicate files, and API method counts:

```bash
bash .github/scripts/verify-repository-hygiene.sh
```

### Headless Regression Tests

After `buildGhidraScript` or `clean verify` populates `build/ghidra-script/`, run the headless Ghidra function-mutation regression test on Linux x86-64 (requires `gcc` and `nm`):

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Exact Local CI Sequence

Run these three commands in order to match the `verify` job in `.github/workflows/ci.yml`:

```bash
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```
