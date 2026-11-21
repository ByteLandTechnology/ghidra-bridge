# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- Put all Java modules under `modules/`. The root project must not own source files in `src/`.
- Keep Ghidra API imports (`ghidra.*`) in `modules/adapter` and `modules/launcher`.
- Keep `ghidra-bridge.jar` free of third-party runtime dependencies.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` after you change the public API.
- Do not commit generated launcher scripts (`Bridge.java`, `GhidraMcp.java`) or `build/` files.

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
- `./gradlew --no-daemon clean verify`: Verifies architecture rules, contracts, and scripts.
- `./gradlew --no-daemon :wire:test :contracts:test`: Runs the wire and contract JUnit tests.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Tests function mutations in headless Ghidra on Linux x86-64 after `verify` (`gcc` and `nm`).
- `bash .github/scripts/package-release.sh`: Builds and verifies the local release archive.
