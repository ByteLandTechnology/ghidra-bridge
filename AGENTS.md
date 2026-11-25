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

### Full Build and Verification (`clean verify`)

Run the full local Gradle verification check. CI runs `./gradlew --no-daemon verify` on a new checkout for pull requests and release archives. Keep `clean verify` locally to delete previous build output:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs:
- `check`: JUnit tests and checks across all 8 Java subprojects.
- `verifyApiContracts`: Checks that tracked contracts match generated output.
- `verifyDistribution`: Builds `build/ghidra-script/` (`Bridge.java`, `GhidraMcp.java`, `ghidra-bridge.jar`) and compiles generated scripts against Ghidra (`compileGeneratedScripts`).
- `verifyArchitecture`: Checks that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Repository Hygiene Check

Check tracked files, build artifacts, duplicates, API method counts, and SHA-pinned GitHub Actions:

```bash
bash .github/scripts/verify-repository-hygiene.sh
```

### Headless Regression Tests

Run the headless function-mutation regression test on Linux x86-64 after `buildGhidraScript`, `verify`, or `clean verify`. This test needs `gcc` and `nm`:

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
