# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Architecture and contracts

- Use JDK 21 and Ghidra 12.1 or newer, and set `GHIDRA_INSTALL_DIR`.
- Always use the Gradle Wrapper (`./gradlew`) in this repository.
- Keep Ghidra API imports in `modules/adapter` and `modules/launcher`.
- Run `./gradlew generateApiContracts` after you change a public API operation.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.

## GitHub Actions

- Pin each external `uses:` step in `.github/workflows/` and `.github/actions/` to a 40-character commit SHA.
- Add a `# vX.Y.Z` version comment after each commit SHA, such as `# v4.4.0`.
- Do not use mutable tags or branch names such as `@v4` or `@main`.
- Keep local composite action paths that start with `./`, such as `./.github/actions/setup-ghidra`.
- Keep weekly `github-actions` updates in `.github/dependabot.yml` for `/` and `/.github/actions/setup-ghidra`.
- Do not add a `gradle` ecosystem to `.github/dependabot.yml` so `gradle/verification-metadata.xml` stays intact.

## Commit messages

- Obey Conventional Commits, such as `fix(wire): reject unknown fields`.
- Use no more than 72 characters on each line, with spaces and list markers counted.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters, with no period at the end.
- Do not add attribution lines to commit messages or pull request text.

## Verification

Before you submit a change, run the local verification suite:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

Repository verification commands:

- `./gradlew --no-daemon clean verify`: Runs tests, `verifyArchitecture`, `verifyApiContracts`, `compileGeneratedScripts`, and `verifyDistribution`.
- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, contract counts, and SHA-pinned GitHub Actions.
- `./gradlew generateApiContracts`: Regenerates `docs/api.md`, `docs/asyncapi.yaml`, and `docs/mcp-tools.json`.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`: Tests function mutations after `./gradlew buildGhidraScript`.
