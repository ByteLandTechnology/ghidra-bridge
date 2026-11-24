# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Environment setup

- **JDK**: Use Java 21 (JDK 21).
- **Ghidra**: Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- **`GHIDRA_INSTALL_DIR`**: Set `GHIDRA_INSTALL_DIR` or `-PghidraInstallDir` to the local Ghidra directory.
  Gradle needs Ghidra to compile `:adapter`, `:launcher`, and generated scripts, and to run Ghidra tests.
- **Gradle Wrapper**: Run `./gradlew` from the repository root. Do not use a system Gradle binary.

## Module layout and repository hygiene

The build defines 8 Java subprojects under `modules/`:

- `:domain` (`modules/domain`)
- `:wire` (`modules/wire`)
- `:contracts` (`modules/contracts`)
- `:runtime` (`modules/runtime`)
- `:adapter` (`modules/adapter`)
- `:launcher` (`modules/launcher`)
- `:transport:websocket` (`modules/transport/websocket`)
- `:transport:mcp` (`modules/transport/mcp`)

Obey these repository rules when you change code:

- Keep all Java source files inside `modules/`. Do not add a root `src/` directory.
- Keep `ghidra.*` API imports inside `modules/adapter` and `modules/launcher`.
- Keep one launcher template in `modules/launcher/src/main/templates/GhidraLauncher.java.template`.
- Do not commit generated launcher scripts (`Bridge.java` or `GhidraMcp.java`), `build/` outputs,
  IDE files, zero-byte files, or exact duplicate files.
- Regenerate `docs/api.md`, `docs/asyncapi.yaml`, and `docs/mcp-tools.json` with
  `./gradlew generateApiContracts`. Do not edit generated contracts by hand.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, with spaces and list markers counted.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, put one blank line after the header and start each line with `- `.
- Do not add attribution lines to commit messages or pull request text.
- Each commit must compile and pass verification checks.

## Verification

### Module checks and unit tests (`check`)

Run JUnit test suites and module checks across all 8 Java subprojects:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon check
```

Run JUnit tests for one subproject when you test a local change:

```bash
./gradlew --no-daemon :domain:test
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon :adapter:test
```

### Full build and verification (`clean verify`)

Run the full Gradle verification gate for pull requests and releases:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

`verify` runs these tasks:

- `check`: Runs JUnit tests and checks across all 8 Java subprojects.
- `verifyApiContracts`: Checks that tracked contracts match generator output.
- `verifyDistribution`: Builds `build/ghidra-script/`, compiles generated scripts, and runs `:launcher:test`.
- `verifyArchitecture`: Checks that no module outside `adapter` and `launcher` imports `ghidra.*`.

### Repository hygiene, headless tests, and release archive

Run these local checks before you submit a change:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, module layout,
  and contract counts.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Runs headless Ghidra function mutation checks on Linux x86-64 after `buildGhidraScript` or
  `clean verify` (requires `gcc` and `nm`).
- `bash .github/scripts/package-release.sh`: Checks `version.txt`,
  `.release-please-manifest.json`, and JAR `Implementation-Version`, then builds the release
  archive and SHA-256 checksum in `build/release/`.

Run these three commands in sequence to match the `verify` job in `.github/workflows/ci.yml`:

```bash
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

## Releases

- CI keeps the `verify -> release -> publish` job sequence without cross-job workflow artifacts.
- `release-please` creates a `v<version>` tag and stages a draft GitHub release
  (`"draft": true` and `"force-tag-creation": true` in `release-please-config.json`).
- `publish` gets `needs.release.outputs.sha` with `persist-credentials: false` and checks
  `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft == true`,
  `.release-please-manifest.json`, and `version.txt` before Gradle runs.
- `publish` runs `package-release.sh` (which runs `clean verify`) and
  `tests/function_mutation_regression.py` before asset upload.
- `publish` checks non-empty `.zip` and `.sha256` files, verifies `sha256sum -c`, uploads both
  assets with `gh release upload --clobber`, and promotes the draft release in place last with
  `gh api --method PATCH` and `-F draft=false`.
- A failure in `publish` leaves the GitHub release hidden as a draft until a maintainer reruns
  the failed jobs.
