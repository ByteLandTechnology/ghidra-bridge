# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## Environment

- Use Java 21 (JDK 21).
- Use Ghidra 12.1 or newer (CI uses Ghidra `12.1.2`).
- Set `GHIDRA_INSTALL_DIR` to the local Ghidra installation directory, or pass `-PghidraInstallDir=/path/to/ghidra`.
- Run `./gradlew` from the repository root instead of a system Gradle binary.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and contracts

The build defines 8 Java modules under `modules/`:

- `:domain` (`modules/domain`)
- `:wire` (`modules/wire`)
- `:contracts` (`modules/contracts`)
- `:runtime` (`modules/runtime`)
- `:adapter` (`modules/adapter`)
- `:launcher` (`modules/launcher`)
- `:transport:websocket` (`modules/transport/websocket`)
- `:transport:mcp` (`modules/transport/mcp`)

Obey these module and repository rules:

- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Keep `ghidra-bridge.jar` free of third-party dependencies.
- Run `./gradlew --no-daemon generateApiContracts` when you change a public method or schema.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Do not commit build directories, IDE files, generated scripts, zero-byte files, or duplicate files.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - A module name, such as `domain`, `wire`, `runtime`, `adapter`, `mcp`, or `launcher`.
  - `docs`: the documents.
  - `build`: build files, such as `build.gradle` and `settings.gradle`.
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
- Each commit must compile and pass checks.

## Verification

Run these local checks before you commit or submit a pull request:

- `actionlint`: Checks GitHub Actions workflows and composite action metadata.
- `shellcheck .github/scripts/*.sh`: Checks repository shell scripts.
- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, duplicates, URLs, and MCP tool names.
- `./gradlew --no-daemon verifyArchitecture`: Checks module import boundaries without Ghidra.
- `./gradlew --no-daemon check`: Runs JUnit tests and module checks across all 8 Java modules.
- `./gradlew --no-daemon :domain:test`: Runs JUnit tests for one module without Ghidra.
- `./gradlew --no-daemon verify`: Verifies module checks, contracts, distribution files, generated scripts, and architecture rules.
- `./gradlew --no-daemon clean verify`: Runs the clean verification suite that CI executes.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`: Runs headless function mutation tests on Linux x86-64 after `buildGhidraScript` or `clean verify`.
