# Contribute to Ghidra Bridge

## Configure the build

Use Java 21. To run unit tests in the six Ghidra-free modules without Ghidra, run:

```bash
./gradlew --no-daemon testWithoutGhidra verifyArchitecture
```

To compile `:adapter` and `:launcher` and run the full verification suite, install Ghidra 12.1 and set `GHIDRA_INSTALL_DIR` to the Ghidra installation directory:

```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra ./gradlew --no-daemon clean verify
```

Use the Gradle Wrapper in this repository. Read [the architecture guide](docs/architecture.md) before you change a module boundary.

## Change the code

Put a change in the module that owns the function. Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.

When you change a public method, update the service, the wire schema, and the adapter. Run `./gradlew generateApiContracts` to update the generated documents.

Do not edit generated contracts by hand. Do not commit files from a build directory.

## Submit a change

For changes in Ghidra-free modules when Ghidra is not installed, run `./gradlew --no-daemon testWithoutGhidra verifyArchitecture`. Before merge, run the full verification suite with Ghidra (`./gradlew --no-daemon clean verify`) and `bash .github/scripts/verify-repository-hygiene.sh`. State the behavior change and its effect on users in the pull request.

Use a Conventional Commit message. For example: `fix(wire): reject unknown fields`. The commit type sets the next release version. See [the development guide](docs/development.md#releases).

Report a security problem as described in [SECURITY.md](SECURITY.md). Do not put a security report in a public issue.
