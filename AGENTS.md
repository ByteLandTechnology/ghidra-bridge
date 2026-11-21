# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.
- Keep lines to 100 characters or fewer where possible.

## Prerequisites and build

- Use JDK 21 and Ghidra 12.1 or newer.
- Set `GHIDRA_INSTALL_DIR` to the Ghidra installation path, or pass `-PghidraInstallDir`.
- Always use the Gradle Wrapper (`./gradlew`) in this repository.

## Architecture and generated files

- Put each change in the module under `modules/` that owns the function.
- Keep `ghidra.*` imports strictly inside `modules/adapter` and `modules/launcher`.
- When you add or change a public API operation, update `modules/domain`, `modules/adapter`,
  and `modules/wire`, then regenerate public contracts:
  ```bash
  ./gradlew generateApiContracts
  ```
- Do not edit generated files by hand:
  - `docs/api.md`
  - `docs/asyncapi.yaml`
  - `docs/mcp-tools.json`
- Do not commit generated launcher scripts (`Bridge.java`, `GhidraMcp.java`) or `build/` output.

## GitHub Actions and Renovate

- Pin every third-party `uses:` reference in `.github/workflows/` and `.github/actions/` to a
  verified 40-character commit SHA with a `# vX.Y.Z` version comment.
- Keep local composite action invocations such as `./.github/actions/setup-ghidra` as relative
  repository paths.
- `renovate.json` manages GitHub Actions digests:
  - `enabledManagers` is restricted to `["github-actions"]` so Gradle dependency checksums in
    `gradle/verification-metadata.xml` stay untouched.
  - `helpers:pinGitHubActionDigests` converts any newly added tag reference into an immutable
    40-character commit SHA with a version comment.
  - `packageRules` group weekly `minor`, `patch`, and `digest` updates across `.github/workflows/`
    and `.github/actions/` into one pull request (`github-actions (non-major)`).
  - Major action updates run on the weekly schedule in separate pull requests for isolated review.
- Organization administrators must install and authorize the Renovate GitHub App on
  `ByteLandTechnology/ghidra-bridge` for scheduled updates to run.

## Local verification

Before you submit a change, run the repository verification commands from `docs/development.md`:

```bash
./gradlew --no-daemon clean verify
bash .github/scripts/verify-repository-hygiene.sh
```

What these commands verify:

- `./gradlew --no-daemon clean verify`:
  - `verifyArchitecture`: Checks that only `modules/adapter` and `modules/launcher` import
    `ghidra.*` packages.
  - `verifyApiContracts`: Checks that `docs/api.md`, `docs/asyncapi.yaml`, and
    `docs/mcp-tools.json` match generator output.
  - `compileGeneratedScripts`: Checks that generated `Bridge.java` and `GhidraMcp.java` compile.
  - `verifyDistribution`: Checks that `build/ghidra-script/` contains `Bridge.java`,
    `GhidraMcp.java`, and a self-contained `ghidra-bridge.jar`.
- `bash .github/scripts/verify-repository-hygiene.sh`:
  - Checks tracked files for ignored files, generated artifacts, zero-byte files, duplicate files,
    stale build paths, and the 56-method table in `docs/api.md`.

To run unit tests and headless function mutation regression tests on Linux x86-64 (requires `gcc`
and `nm`):

```bash
./gradlew --no-daemon :wire:test :contracts:test
./gradlew --no-daemon buildGhidraScript
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

## Commit messages

- Obey Conventional Commits (`fix`, `feat`, `docs`, `ci`, `test`, `refactor`, `build`).
- Note how `release-please` reads commit types on `main`:
  - `fix` increases the patch version.
  - `feat` increases the minor version.
  - `!` or `BREAKING CHANGE:` increases the major version.
  - `docs`, `ci`, and `test` do not start a release on their own.
- Use 72 characters or fewer on each line.
- Start the summary with a lowercase imperative verb and omit the trailing period.
- If you write a body, put one blank line after the header and write one `- ` item per line.
- Do not add attribution lines such as `Co-Authored-By` to commit messages or pull request text.
