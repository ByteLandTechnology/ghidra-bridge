# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- Use JDK 21 and Ghidra 12.1 or newer.
- Put each change in the module under `modules/` that owns the function.
- Keep `ghidra.*` API imports in `modules/adapter` and `modules/launcher`.
- Run `./gradlew generateApiContracts` after a public interface change.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Do not commit build output, local IDE files, or generated launcher scripts.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
- Use these scopes:
  - A module name, such as `domain`, `wire`, `contracts`, `runtime`, `adapter`, or `launcher`.
  - A transport name, such as `mcp` or `websocket`.
  - `docs`: the documents.
  - `build`: Gradle build and wrapper files.
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

Set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory before you run checks:

- `./gradlew --no-daemon clean verify`: Checks architecture, contracts, and distribution files.
- `./gradlew --no-daemon :wire:test :contracts:test`: Runs the wire and contract unit tests.
- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files and repository hygiene.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Runs headless function mutation checks on `build/ghidra-script/` (`gcc` and `nm` required).
- `bash .github/scripts/package-release.sh`: Builds and verifies the release archive locally.

Local runs include `clean` to clear stale build output.
CI runs `./gradlew --no-daemon verify :wire:test :contracts:test` on fresh checkouts.
