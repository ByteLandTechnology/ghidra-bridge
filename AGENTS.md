# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, tool descriptions, commit messages, and documentation.

## Modules and files

- Use Java 21 and the Gradle Wrapper (`./gradlew` on Linux and macOS, `.\gradlew.bat` on Windows).
- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Keep zero third-party runtime dependencies in `ghidra-bridge.jar`.
- Keep strict Gradle dependency verification in `gradle.properties`.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` when a public method or schema changes.
- On Windows, run `git config --global core.autocrlf false` before Git checkout so contract files keep LF line endings.
- Do not commit build output, binary files, zero-byte files, or duplicate files.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - `domain`, `wire`, `contracts`, `runtime`, `adapter`, `launcher`, `websocket`, or `mcp`: code in `modules/`.
  - `docs`: documents and generated contracts in `docs/`.
  - `build`: Gradle scripts and wrapper files.
  - `ci`: workflows, composite actions, and scripts in `.github/`.
  - `test`: regression scripts in `tests/`.
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

Run local checks with the Gradle Wrapper, `bash`, and Python:

- `bash .github/scripts/verify-repository-hygiene.sh`: Verifies tracked files, launcher templates, duplicates, and the documented method count.
- `./gradlew --no-daemon verifyArchitecture verifyGhidraDetection`: Runs fast boundary and synthetic Ghidra path checks without a local Ghidra installation.
- `./gradlew --no-daemon verifyGhidraDetection` (`.\gradlew.bat --no-daemon verifyGhidraDetection` on Windows): Verifies `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, `Ghidra.app` bundles, version order, and Windows folders.
- `./gradlew --no-daemon :wire:test :contracts:test` (`.\gradlew.bat --no-daemon :wire:test :contracts:test` on Windows): Runs fast wire and contract unit tests.
- `GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.4_PUBLIC ./gradlew --no-daemon clean verify`: Runs full repository verification against Ghidra `12.1.4`.
- `GHIDRA_INSTALL_DIR=/path/to/ghidra_12.1.2_PUBLIC ./gradlew --no-daemon clean verify`: Verifies compatibility with the Ghidra `12.1.2` floor release.
- `.\gradlew.bat -PghidraInstallDir=C:\ghidra_12.1.4_PUBLIC --no-daemon clean verify`: Runs full repository verification on Windows.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`: Runs headless function mutation tests with the native CPU ELF fixture (`--arch x86_64` or `--arch aarch64`).
- `python tests/function_mutation_regression.py "%GHIDRA_INSTALL_DIR%\support\analyzeHeadless.bat"`: Runs headless function mutation tests on Windows.
