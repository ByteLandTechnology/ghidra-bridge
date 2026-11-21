# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
Local hooks and CI checks verify compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, pull request text, and documentation.
- Write short sentences in active voice with simple verb forms.
- Use "must" for a requirement and "can" for a possibility.
- Do not use contractions or phrasal verbs.
- Write "for example" and "that is" instead of Latin abbreviations.

## Modules and files

- All Java modules live in `modules/` and follow the one-way dependency graph in [docs/architecture.md](docs/architecture.md):
  - `modules/domain` (`:domain`): service interfaces, domain records, and domain exceptions.
  - `modules/wire` (`:wire`): unified 56-method `ApiRegistry` and JSON codecs.
  - `modules/contracts` (`:contracts`): generator for `docs/api.md` and `docs/asyncapi.yaml`.
  - `modules/runtime` (`:runtime`): single-request dispatcher and session lifecycle control.
  - `modules/adapter` (`:adapter`): Ghidra service implementations and transaction sessions.
  - `modules/transport` (`:transport`): parent directory for network transport modules.
  - `modules/transport/websocket` (`:transport:websocket`): WebSocket JSON-RPC 2.0 server and client.
  - `modules/transport/mcp` (`:transport:mcp`): MCP Streamable HTTP server and `docs/mcp-tools.json` generator.
  - `modules/launcher` (`:launcher`): bootstrap entry point and Ghidra script templates.
- Keep `ghidra.*` API imports in `modules/adapter` and `modules/launcher` only.
- Do not put source files in a root `src/` directory.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` when you add or change a public method or schema.
- Do not commit generated scripts (`Bridge.java`, `GhidraMcp.java`), `build/` output, zero-byte files, or duplicate files.
- When you change an English document that has translations in `docs/zh/` or `docs/ja/`, update the translations too.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line.
  Count spaces and list markers in this limit.
- Use lowercase letters for the type and the scope.
- All standard Conventional Commit types are permitted: `build`, `chore`, `ci`, `docs`, `feat`, `fix`, `perf`, `refactor`, `revert`, `style`, and `test`.
- `release-please` reads Conventional Commit messages on `main` to select the next version:
  - `fix`: increases the patch version, such as `1.4.1`.
  - `feat`: increases the minor version, such as `1.5.0`.
  - `!` after the type or scope, or a `BREAKING CHANGE:` footer: increases the major version.
  - Other types, such as `docs`, `ci`, and `test`: do not start a release on their own.
- Use these scopes:
  - `domain`: code in `modules/domain`.
  - `wire`: code in `modules/wire`.
  - `contracts`: code in `modules/contracts`.
  - `runtime`: code in `modules/runtime`.
  - `adapter`: code in `modules/adapter`.
  - `transport`: shared transport files in `modules/transport`.
  - `websocket` or `transport:websocket`: code in `modules/transport/websocket`.
  - `mcp` or `transport:mcp`: code in `modules/transport/mcp`.
  - `launcher`: code in `modules/launcher`.
  - `docs`: documents in `docs/` and root Markdown files.
  - `build`: Gradle build files, wrapper files, and dependency metadata.
  - `ci`: workflows, hooks, and scripts in `.github/` and `.pre-commit-config.yaml`.
  - If a commit changes more than one scope, do not write a scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- Pull request titles must obey the same Conventional Commit header rules.
- The body is optional for a small change that needs no explanation.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
  - If an item is too long, write a shorter sentence or divide it.
- The body rules do not apply to footers.
- Git `Merge` commits and `chore(main): release` commits from `release-please` are exempt from `commit-msg` rules.
- Do not add attribution lines such as `Co-Authored-By` to commit messages or pull request text.
- Each commit must compile and pass verification checks.

## Verification

Install the `pre-commit` and `commit-msg` Git hooks once per clone:

```bash
pre-commit install --install-hooks
```

Run the repository verification suite before you commit or open a pull request:

```bash
pre-commit run --all-files
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
```

Run unit tests and headless regression checks when you change wire, contract, or function mutation code:

```bash
./gradlew --no-daemon :wire:test :contracts:test
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

To build and verify the release archive locally, run:

```bash
bash .github/scripts/package-release.sh
```

The verification tasks check:

- `pre-commit run --all-files`: runs `.github/scripts/verify-repository-hygiene.sh` for tracked file hygiene and `docs/api.md` method counts.
- `verifyArchitecture`: verifies that only `modules/adapter` and `modules/launcher` import `ghidra.*` classes.
- `verifyApiContracts`: verifies that `docs/api.md`, `docs/asyncapi.yaml`, and `docs/mcp-tools.json` match the code.
- `compileGeneratedScripts`: verifies that generated `Bridge.java` and `GhidraMcp.java` scripts compile.
- `verifyDistribution`: verifies the contents of `build/ghidra-script/`.
