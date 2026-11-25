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

Run the full Gradle verification gate used in pull requests and release archives:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `check`: JUnit tests and checks across all 8 Java subprojects.
- `verifyApiContracts`: Checks that checked-in contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Verifies that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Repository Hygiene Check

Check tracked files for build artifacts, stale paths, zero-byte files, duplicate files, and API method counts:

```bash
bash .github/scripts/verify-repository-hygiene.sh
```

### Pre-Commit Hooks

Install the local `pre-commit` and `commit-msg` Git hooks from `.pre-commit-config.yaml`:

```bash
pre-commit install --install-hooks
```

Container and sandbox environments often set global `core.hooksPath=/dev/null`, which blocks `pre-commit install`. Unset the global setting (`git config --global --unset-all core.hooksPath`), or install hooks for this repository only:

```bash
GIT_CONFIG_GLOBAL=/dev/null pre-commit install --install-hooks
git config --local core.hooksPath .git/hooks
```

Run file, syntax, and repository hygiene hooks directly, and check a commit message file without installed Git hooks:

```bash
pre-commit run --all-files
pre-commit run --hook-stage commit-msg --commit-msg-filename .git/COMMIT_EDITMSG
```

### Headless Regression Tests

After `buildGhidraScript` or `clean verify` populates `build/ghidra-script/`, run the headless Ghidra function-mutation regression test on Linux x86-64 (requires `gcc` and `nm`):

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

### Exact Local CI Sequence

Run these commands in order to match the `verify` job in `.github/workflows/ci.yml`:

```bash
pre-commit run --all-files
pre-commit run --hook-stage commit-msg --commit-msg-filename .git/COMMIT_EDITMSG
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

## Commit Messages

- Obey Conventional Commits in commit messages and pull request titles.
- Use no more than 72 characters on each line. Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- Permitted types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- For an incompatible change, put `!` after the type or scope and add a `BREAKING CHANGE:` footer.
- Optional scopes are:
  - Module scopes from `settings.gradle`: `domain`, `wire`, `contracts`, `runtime`, `adapter`, `transport`, `websocket`, `mcp`, and `launcher`.
  - Repository scopes: `docs`, `build`, `ci`, and `test`.
  - If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- The body list rules do not apply to footers (`BREAKING CHANGE:`, `Fixes #...`, `Closes #...`, `Resolves #...`, and `Refs:`).
- Do not add attribution trailers such as `Co-authored-by:` to commit messages or pull request text.
- CI exempts Git `Merge` commits, `release-please` `chore(main): release` commits, and GitHub squash trailers on `main` pushes.
