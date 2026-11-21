# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Architecture and files

- Put each change in the module that owns the function.
- Import `ghidra.*` classes only in `modules/adapter` and `modules/launcher`.
- Keep zero third-party dependencies in the `ghidra-bridge.jar` output.
- Keep `org.gradle.dependency.verification=strict` active in `gradle.properties`.
- Record SHA-256 checksums for build and test dependencies in `gradle/verification-metadata.xml`.
- Do not edit generated contracts (`docs/api.md`, `docs/asyncapi.yaml`, `docs/mcp-tools.json`)
  by hand. Run `./gradlew generateApiContracts` after public interface changes.
- Use UTF-8 text with LF line endings across tracked files, contracts, and Unix scripts.
  Keep `gradlew.bat` in CRLF.

## Formatting and style

- Format Java source files with 2-space Google style (`googleJavaFormat` in Spotless).
- Format Groovy Gradle scripts (`build.gradle`, `settings.gradle`, `gradle/*.gradle`) with
  2-space indentation in Spotless.
- A line in a Java or Gradle file must not exceed 100 characters.
- Lint and format Python files in `tests/` with Ruff (`--select E,F,I,EXE`, 88-character width).
- Do not put a shebang line on a non-executable Python script.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, including spaces and list markers.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- Do not add attribution lines to commit messages or pull request text.
- Each commit must compile and pass verification checks.

## Verification

Apply formatting locally before you commit:

```bash
./gradlew --no-daemon spotlessApply
ruff format tests/
ruff check --select E,F,I,EXE --fix tests/
```

Run all style, hygiene, contract, architecture, and distribution checks locally:

```bash
./gradlew --no-daemon spotlessCheck
ruff check --select E,F,I,EXE tests/
ruff format --check tests/
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```
