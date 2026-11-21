# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Do not edit generated contracts (`docs/api.md`, `docs/asyncapi.yaml`, `docs/mcp-tools.json`)
  by hand. Run `./gradlew generateApiContracts` after an interface change.
- Keep LF line endings on text files, contracts, and shell scripts.
- Keep CRLF line endings on `gradlew.bat`.
- Format Java files with `google-java-format` (2-space indentation).
- A Java line must not exceed 100 characters.
- Format Python files in `tests/` with `ruff` (4-space indentation).
- Do not put a shebang line in a Python script that is not executable.
- Do not add external Gradle plugins to `build.gradle` or change
  `gradle/verification-metadata.xml` for formatting tools.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- Do not add attribution to commit messages or pull request text.
- Each commit must compile and pass verification.

## Verification

Format Java and Python changes in place with `.github/scripts/verify-formatting.sh --fix`.

Run these checks before you open a pull request:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, build artifacts,
  duplicates, and contract method counts.
- `bash .github/scripts/verify-formatting.sh`: Verifies `google-java-format`, the 100-character
  Java line width, `ruff check`, and `ruff format --check`.
- `./gradlew --no-daemon clean verify`: Verifies architecture boundaries, API contracts,
  generated launcher scripts, and distribution output.
