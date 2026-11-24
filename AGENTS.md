# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Build configuration

- Use Java 21 (JDK 21) and Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- Set `GHIDRA_INSTALL_DIR` to the Ghidra directory, or pass `-PghidraInstallDir=/path/to/ghidra`.
  Gradle uses Ghidra to compile `:adapter`, `:launcher`, and scripts, and to run Ghidra tests.
- Run `./gradlew` from the repository root. Do not use a system Gradle binary.

## Modules and files

The build defines 8 Java modules under `modules/`:

- `:domain` (`modules/domain`)
- `:wire` (`modules/wire`)
- `:contracts` (`modules/contracts`)
- `:runtime` (`modules/runtime`)
- `:adapter` (`modules/adapter`)
- `:launcher` (`modules/launcher`)
- `:transport:websocket` (`modules/transport/websocket`)
- `:transport:mcp` (`modules/transport/mcp`)

Obey these module and file rules:

- Put all Java modules under `modules/`. The root project must not own source files in `src/`.
- Keep Ghidra API imports (`ghidra.*`) in `modules/adapter` and `modules/launcher`.
  The `verifyArchitecture` task checks this rule.
- Keep `ghidra-bridge.jar` free of third-party runtime dependencies.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` after you change the public API.
- Do not commit `build/` files, IDE files, or generated scripts (`Bridge.java`, `GhidraMcp.java`).
- Do not commit zero-byte files or duplicate files.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - A module name, such as `domain`, `wire`, `contracts`, `runtime`, `adapter`, `launcher`,
    `transport`, or `mcp`: its code in `modules/`.
  - `docs`: the documents.
  - `gradle` or `build`: Gradle scripts and wrapper files.
  - `ci`: workflows and scripts in `.github/`.
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
  - If an item is too long, write a shorter sentence or divide it.
- The body rules do not apply to footers.
- Do not add attribution to commit messages or pull request text.
- Each commit must compile and pass verification.

## Verification

Set `GHIDRA_INSTALL_DIR` to a Ghidra 12.1 or newer installation and run local checks:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files and contract counts.
- `./gradlew --no-daemon check`: Runs JUnit tests and module checks across all 8 Java modules.
- `./gradlew --no-daemon :domain:test` or `./gradlew --no-daemon :adapter:test`:
  Runs JUnit tests for one module.
- `./gradlew --no-daemon clean verify`:
  Runs `check`, `verifyApiContracts`, `verifyDistribution`, and `verifyArchitecture`.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Tests function mutations in headless Ghidra on Linux x86-64 after `verify` (`gcc` and `nm`).
- `bash .github/scripts/package-release.sh`: Builds and verifies the local release archive.

Run these three commands in order to match the `verify` job in `.github/workflows/ci.yml`:

```bash
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```
