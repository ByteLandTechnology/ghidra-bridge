# Contribute to Ghidra Bridge

## Set up the build

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

Run `./gradlew --no-daemon clean verify`. State the behavior change and its effect on users in the pull request.

Use a Conventional Commit message. For example: `fix(wire): reject unknown fields`.

Report a security problem as described in [SECURITY.md](SECURITY.md). Do not put a security report in a public issue.
