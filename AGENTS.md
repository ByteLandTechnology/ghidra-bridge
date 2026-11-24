# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and contracts

- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Keep third-party build libraries in `modules/contracts` so `ghidra-bridge.jar` has zero external dependencies.
- Use underscore MCP tool names, such as `ghidra_help` and `ghidra_program`.
- Run `./gradlew generateApiContracts` when a public method or schema changes.
- Do not edit generated contracts in `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Do not mask errors with `|| true` or `continue-on-error: true` in scripts or workflows.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - A module name, such as `domain`, `wire`, `contracts`, `runtime`, `adapter`, `websocket`, `mcp`, or `launcher`.
  - `docs`: the documents.
  - `build`: Gradle files and build configuration.
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

Run local checks that require only JDK 21 and Git:

- `./gradlew --no-daemon verifyRepositoryRules`: Verifies repository hygiene, module imports, contract tokens, GitHub YAML files, and Simplified English.
- `./gradlew --no-daemon :contracts:test`: Runs unit tests for contract generators and repository verifiers.
- `./gradlew --no-daemon :wire:test :contracts:test`: Runs unit tests for wire codecs and contract verifiers.
- `actionlint .github/workflows/ci.yml`: Checks GitHub Actions workflow syntax, expressions, and local action inputs.
- `shellcheck -o check-extra-masked-returns .github/scripts/*.sh`: Checks shell scripts for syntax errors and masked exit codes.

Run full verification with `GHIDRA_INSTALL_DIR` to match the `verify` job in CI:

- `bash .github/scripts/verify-repository-hygiene.sh`: Runs `verifyRepositoryRules` through the strict wrapper script.
- `./gradlew --no-daemon clean verify`: Runs `verifyApiContracts`, `verifyDistribution`, `verifyArchitecture`, and `verifyRepositoryRules`.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`: Runs headless function mutation tests on Linux x86-64.
