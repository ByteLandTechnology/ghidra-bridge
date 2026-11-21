# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` after you change a public method or schema.
- Do not commit build output, generated launcher scripts, zero-byte files, or duplicate files.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All Conventional Commit types are permitted, also `test`.
- For an incompatible change, put `!` after the type or scope.
  Add a `BREAKING CHANGE:` footer.
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
- Each commit must pass verification.

## Verification

Set `GHIDRA_INSTALL_DIR` to a Ghidra 12.1 installation and run repository checks:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files and method counts.
- `./gradlew --no-daemon clean verify`: Checks architecture, contracts, and distribution files.
- `./gradlew --no-daemon :wire:test :contracts:test`: Runs unit and contract tests.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Tests function mutations in an isolated headless Ghidra project.
- `bash .github/scripts/package-release.sh`: Builds the deterministic release archive and checksum.
- `python3 tests/release_archive_reproducibility.py`: Checks `version.txt` whitespace
  normalization, sorted entries, fixed DOS timestamps, and reproducible zip digests.
