# Contribute to Ghidra Bridge

## Configure the build

Use Java 21 and Ghidra 12.1. Set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory.

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

Use the Gradle Wrapper in this repository. Read [the architecture guide](docs/architecture.md) before you change a module boundary.

## Change the code

Put a change in the module that owns the function. Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.

When you change a public method, update the service, the wire schema, and the adapter. Run `./gradlew generateApiContracts` to update the generated documents.

Do not edit generated contracts by hand. Do not commit files from a build directory.

## Submit a change

Install the Git hooks once in your local clone:

```bash
pre-commit install --install-hooks
```

Run the repository checks before you open a pull request:

```bash
pre-commit run --all-files
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
```

`verify` runs JUnit tests across all Java modules (`check`), contract drift checks, script compilation, distribution checks, and architecture boundary checks. It also runs `verifyMcpDocumentation` to check `docs/mcp-tools.json`, the nine guides, and MCP Javadocs. On Linux x86-64, also run `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"` after `clean verify` when you change function or runtime behavior.

State the behavior change and its effect on users in the pull request. Obey the repository rules in [AGENTS.md](AGENTS.md).

## Commit messages

Use the [commit message rules](AGENTS.md#commit-messages). For example: `fix(wire): reject unknown fields`. The commit type sets the next release version. See [the development guide](docs/development.md#releases).

## Report a security problem

Report a security problem as described in [SECURITY.md](SECURITY.md). Do not put a security report in a public issue.
