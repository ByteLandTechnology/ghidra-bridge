# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules across Linux, macOS, and Windows.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and contracts

- The build has eight Java modules under `modules/`: `domain`, `wire`, `contracts`, `runtime`, `adapter`, `launcher`, `transport/websocket`, and `transport/mcp`.
- Put each change in the module that owns the function.
- Keep Ghidra API imports inside `modules/adapter` and `modules/launcher`.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` (or `.\gradlew.bat generateApiContracts` on Windows) after a public API change.
- Do not commit generated launcher scripts, IDE files, zero-byte files, duplicate files, or files from `build/` directories.
- On Windows checkouts, run `git config core.autocrlf false` so contract files keep LF line endings.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- Do not add attribution lines to commit messages or pull request text.
- Each commit must compile and pass verification.

## Verification

Use JDK 21 and Ghidra 12.1 or newer (CI uses Ghidra `12.1.4`).
Set `GHIDRA_INSTALL_DIR` or `GHIDRA_HOME` to a Ghidra installation when Gradle cannot detect Ghidra automatically.
Run `./gradlew --no-daemon check` (or `:domain:test`, `:adapter:test`) to run module JUnit tests.
CI runs `verify` on a new checkout; run `clean verify` locally to delete old build output.

Run every CI check locally on Linux or macOS:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, duplicates, and contract method counts.
- `./gradlew --no-daemon clean verify`: Runs module JUnit tests (`check`), API contract checks, script compilation, distribution checks, and architecture checks.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`: Runs headless function mutation checks.

Run every CI check locally on Windows in PowerShell:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, duplicates, and contract method counts in Git Bash.
- `.\gradlew.bat --no-daemon clean verify`: Runs module JUnit tests (`check`), API contract checks, script compilation, distribution checks, and architecture checks.
- `python tests/function_mutation_regression.py "$env:GHIDRA_INSTALL_DIR\support\analyzeHeadless.bat"`: Runs headless function mutation checks.

Run every CI check locally on Windows in Git Bash:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, duplicates, and contract method counts.
- `./gradlew.bat --no-daemon clean verify`: Runs the clean repository verification task with `gradlew.bat`.
- `python tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless.bat"`: Runs headless function mutation checks.
