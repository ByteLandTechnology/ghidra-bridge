# Agent Guidelines

This document defines the build environment, repository rules, and local verification commands for coding agents and contributors in Ghidra Bridge.

## Environment Setup

- **JDK**: Use Java 21 (JDK 21).
- **Ghidra**: Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- **`GHIDRA_INSTALL_DIR`**: Set `GHIDRA_INSTALL_DIR` to the local Ghidra installation directory (or pass `-PghidraInstallDir=/path/to/ghidra`). Gradle requires a resolved Ghidra installation to compile `:adapter`, `:launcher`, and generated scripts, and to run `:adapter` unit tests and headless regression tests.
- **Gradle Wrapper**: Always invoke `./gradlew` from the repository root rather than a system Gradle binary.
- **Git Hooks**: Run `pre-commit install --install-hooks` once per clone to install the local `pre-commit` and `commit-msg` hooks.

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
- **Simplified Technical English**: Use ASD-STE100 Simplified Technical English for documentation, code comments, commit messages, and pull request text. Write short sentences in active voice, and use "must" for a requirement and "can" for a possibility. Do not use contractions, phrasal verbs, or Latin abbreviations.
- **Translations**: When you change an English document that has translations in `docs/zh/` or `docs/ja/`, update the translations too.

## Commit Messages

- Obey Conventional Commits in commit messages and pull request titles.
- Use no more than 72 characters on each line. Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- Permitted types: `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- `release-please` reads Conventional Commit messages on `main` to select the next version:
  - `fix`: increases the patch version, such as `1.4.1`.
  - `feat`: increases the minor version, such as `1.5.0`.
  - `!` after the type or scope, or a `BREAKING CHANGE:` footer: increases the major version.
  - Other types, such as `docs`, `ci`, and `test`: do not start a release on their own.
- Optional scopes: `domain`, `wire`, `contracts`, `runtime`, `adapter`, `transport`, `websocket` (or `transport:websocket`), `mcp` (or `transport:mcp`), `launcher`, `docs`, `build`, and `ci`. If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters. Do not put a period at the end of the summary.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
  - If an item is too long, write a shorter sentence or divide it.
- The body rules do not apply to footers.
- Git `Merge` commits and `chore(main): release` commits from `release-please` are exempt from `commit-msg` rules.
- Do not add attribution lines such as `Co-Authored-By` to commit messages or pull request text.
- Each commit must compile and pass verification checks.

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

### Pre-Commit Hooks

Install the `pre-commit` and `commit-msg` Git hooks once per clone. Run all hooks before you open a pull request:

```bash
pre-commit install --install-hooks
pre-commit run --all-files
```

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
