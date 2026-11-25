# Agent Guidelines

This document defines the build environment, repository rules, and local verification commands for coding agents and contributors in Ghidra Bridge.

## Environment Setup

- **JDK**: Use Java 21 (JDK 21).
- **Ghidra**: Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- **`GHIDRA_INSTALL_DIR`**: Set `GHIDRA_INSTALL_DIR` to the local Ghidra installation directory (or pass `-PghidraInstallDir=/path/to/ghidra`). Gradle requires a resolved Ghidra installation to compile `:adapter`, `:launcher`, and generated scripts, and to run `:adapter` unit tests and headless regression tests.
- **Gradle Wrapper**: Always invoke `./gradlew` from the repository root rather than a system Gradle binary.
- **Git Hooks**: Run `./gradlew --no-daemon installGitHooks` (or `git config --local core.hooksPath .githooks`) to activate `.githooks/pre-commit` and `.githooks/commit-msg`. Local `check` and `verify` tasks also configure `.githooks`.

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

## Commit Messages

- Obey Conventional Commits (`<type>(<scope>): <summary>` or `<type>: <summary>`). Pull request titles must obey the same header rules.
- Use no more than 72 characters on each line. Count spaces and list markers in this limit.
- Use lowercase letters for the type and the optional scope.
- Permitted types: `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- For an incompatible change, put `!` after the type or scope. Add a `BREAKING CHANGE:` footer.
- Permitted scopes: `domain`, `wire`, `contracts`, `runtime`, `adapter`, `transport`, `websocket`, `mcp`, `launcher`, `docs`, `build`, `ci`, and `test`. If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters. Do not put a period at the end of the summary.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- The body rules do not apply to footers.
- Do not add attribution lines such as `Co-authored-by` to commit messages or pull request text.
- Git `Merge` commits, `release-please` `chore(main): release` commits, and GitHub squash trailers on `main` pushes are exempt.

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

Run the full Gradle verification gate used in pull requests and release archives:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `installGitHooks`: Sets local `core.hooksPath` to `.githooks` during local Gradle runs.
- `check`: JUnit tests and checks across all 8 Java subprojects.
- `verifyApiContracts`: Checks that checked-in contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Verifies that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Repository Hygiene Check

Check tracked files for build artifacts, stale paths, zero-byte files, duplicate files, and API method counts:

```bash
bash .github/scripts/verify-repository-hygiene.sh
```

### Commit Message Check

Check commit headers, 72-character line limits, scopes, and list bodies (or validate a commit range and pull request title):

```bash
bash .github/scripts/verify-commit-messages.sh
bash .github/scripts/verify-commit-messages.sh --pr-title "fix(wire): reject unknown fields" --range origin/main..HEAD
```

### Headless Regression Tests

After `buildGhidraScript` or `clean verify` populates `build/ghidra-script/`, run the headless Ghidra function-mutation regression test on Linux x86-64 (requires `gcc` and `nm`):

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Exact Local CI Sequence

Run these four commands in order to match the `verify` job in `.github/workflows/ci.yml`:

```bash
bash .github/scripts/verify-repository-hygiene.sh
bash .github/scripts/verify-commit-messages.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```
