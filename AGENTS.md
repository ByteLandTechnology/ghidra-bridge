# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, pull request text, and documentation.
- Keep sentences short and clear. An instruction has at most 20 words, and a description has at most 25 words.
- Keep each paragraph to six sentences or fewer.
- Use active voice. Use `must` for a requirement and `can` for a possibility.
- Do not use `should`, `may`, `might`, `could`, or `would`.
- Use simple words such as `make sure`, `let`, `get`, `use`, and `through`. Do not use `ensure`, `allow`, `obtain`, `utilize`, or `via`.
- Do not use contractions, phrasal verbs, nontechnical `-ing` forms, or Latin abbreviations such as `"e.g."`, `"i.e."`, and `"etc."`.

## Modules and architecture

- Use Java 21, Ghidra 12.1, and the Gradle Wrapper (`./gradlew`).
- Keep zero third-party dependencies in the runtime JAR (`ghidra-bridge.jar`).
- Put all source code in `modules/`: `domain`, `wire`, `contracts`, `runtime`, `adapter`, `transport/websocket`, `transport/mcp`, and `launcher`.
- Do not put source files in a root `src/` directory.
- Keep `ghidra.*` imports in `modules/adapter` and `modules/launcher` only.
- Keep `domain`, `wire`, `contracts`, `runtime`, `websocket`, and `mcp` free of Ghidra API classes.
- Stop untyped JSON values at `modules/wire`. Keep domain records and service interfaces typed.
- When you change a public method, update `modules/domain`, `modules/adapter`, and `modules/wire`, then run `./gradlew generateApiContracts`.
- Do not edit generated contracts (`docs/api.md`, `docs/asyncapi.yaml`, `docs/mcp-tools.json`) or generated scripts (`Bridge.java`, `GhidraMcp.java`) by hand.
- Do not commit build output, ignored files, zero-byte files, or duplicate files.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line. Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- Permitted types are `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- `release-please` reads Conventional Commit headers to select the next version:
  - `fix`: Increases the patch version, such as `1.2.1`.
  - `feat`: Increases the minor version, such as `1.3.0`.
  - A `!` after the type or scope or a `BREAKING CHANGE:` footer: Increases the major version.
  - Other types, such as `docs`, `ci`, and `test`: Do not start a release on their own.
- Use these scopes:
  - `domain`, `wire`, `contracts`, `runtime`, `adapter`, `transport`, `websocket`, `mcp`, `launcher`: the code in `modules/`.
  - `docs`: the documents in `docs/` and root Markdown files.
  - `build`: Gradle files, wrapper files, and release configuration.
  - `ci`: workflows, actions, hooks, and scripts in `.github/` and `.githooks/`.
  - `test`: regression scripts and test suites.
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
- Git `Merge` commits and `chore(main): release` commits from `release-please` are exempt.
- Do not add attribution lines such as `Co-Authored-By` to commit messages or pull request text.
- Each commit must compile and pass verification.

## Verification

Install the Git hooks and run the verification suite before you submit a change:

```bash
./gradlew --no-daemon installGitHooks
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
bash .github/scripts/verify-commit-messages.sh
```

The tasks, hooks, and scripts check these rules:

- `./gradlew --no-daemon installGitHooks`: Sets `core.hooksPath` to `.githooks` in local clones when `CI` is unset.
- `.githooks/pre-commit`: Runs `verify-repository-hygiene.sh` and `./gradlew --no-daemon verifyArchitecture`.
- `.githooks/commit-msg`: Validates the commit message file with `verify-commit-messages.sh`.
- `./gradlew --no-daemon clean verify`: Runs `installGitHooks` locally and checks `verifyArchitecture`, `verifyApiContracts`, `compileGeneratedScripts`, and `verifyDistribution`.
- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, zero-byte files, duplicate files, and the 56-method count in `docs/api.md`.
- `bash .github/scripts/verify-commit-messages.sh`: Checks `HEAD` by default, or checks `--file`, `--commit`, `--range`, and `--title`.
