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

Install the Git hooks and run the local verification suite before you open a pull request:

```bash
./gradlew --no-daemon installGitHooks
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
bash .github/scripts/verify-commit-messages.sh
```

State the behavior change and its effect on users in the pull request.

## Commit messages

Use the [commit message rules](AGENTS.md#commit-messages). For example: `fix(wire): reject unknown fields`. The commit type sets the next release version. See [the development guide](docs/development.md#releases).

Report a security problem as described in [SECURITY.md](SECURITY.md). Do not put a security report in a public issue.
