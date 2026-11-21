# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Architecture and modules

- Keep all Java modules in `modules/`: `:domain`, `:wire`, `:contracts`, `:runtime`,
  `:adapter`, `:transport:websocket`, `:transport:mcp`, and `:launcher`.
- Do not put source files in a root `src/` directory.
- Keep `ghidra.*` imports in `modules/adapter` and `modules/launcher` only.
  The six Ghidra-free modules (`:domain`, `:wire`, `:contracts`, `:runtime`,
  `:transport:websocket`, and `:transport:mcp`) must not import Ghidra classes.
- Keep `ghidra-bridge.jar` free of third-party runtime dependencies.
- When you change a public method or schema, update `:domain`, `:wire`, and `:adapter`,
  then run `./gradlew --no-daemon generateApiContracts`.
- Do not edit generated contracts (`docs/api.md`, `docs/asyncapi.yaml`,
  `docs/mcp-tools.json`) or generated scripts (`Bridge.java`, `GhidraMcp.java`) by hand.
- Do not commit build output, temporary files, or IDE configuration files.

## Verification

Always use the Gradle Wrapper (`./gradlew --no-daemon`).

### Fast checks without Ghidra (JDK 21 only)

When `GHIDRA_INSTALL_DIR` is not set, or when you change Ghidra-free modules, run unit tests
across `:domain`, `:wire`, `:contracts`, `:runtime`, `:transport:websocket`, and
`:transport:mcp` plus the architecture boundary check:

```bash
./gradlew --no-daemon testWithoutGhidra verifyArchitecture
```

If you changed public schemas or contracts, also check contract drift:

```bash
./gradlew --no-daemon verifyApiContracts
```

### Full Ghidra verification

Before you merge a change or prepare a release, set `GHIDRA_INSTALL_DIR` to Ghidra 12.1 or
newer and run the full verification suite:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

`verify` runs `check` across all eight Java subprojects (including `:adapter` unit tests),
`verifyApiContracts`, `verifyDistribution`, and `verifyArchitecture`.

On Linux x86-64 with `gcc` and `nm`, also run the headless mutation regression test when you
change function or session mutations:

```bash
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, including spaces and list markers.
- Use lowercase letters for the type and the optional scope.
- Use these scopes:
  - A module name, such as `domain`, `wire`, `contracts`, `runtime`, `adapter`,
    `websocket`, `mcp`, or `launcher`.
  - `docs`: documentation files.
  - `build`: Gradle build and wrapper files.
  - `ci`: workflows and scripts in `.github/`.
  - If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- Do not add attribution lines to commit messages or pull request text.
