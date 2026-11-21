# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Architecture and repository hygiene

- Use JDK 21 and Ghidra 12.1 or newer. Set `GHIDRA_INSTALL_DIR` or `-PghidraInstallDir`.
- Keep all Java source files inside `modules/`. Do not add a root `src/` directory.
- Keep `ghidra.*` API imports inside `modules/adapter` and `modules/launcher`.
- Keep one launcher template in `modules/launcher/src/main/templates/GhidraLauncher.java.template`.
- Do not commit generated launcher scripts (`Bridge.java` or `GhidraMcp.java`), `build/` outputs,
  zero-byte files, or exact duplicate files.
- Regenerate `docs/api.md`, `docs/asyncapi.yaml`, and `docs/mcp-tools.json` with
  `./gradlew generateApiContracts`. Do not edit generated contracts by hand.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, including spaces and list markers.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, put one blank line after the header and start each line with `- `.
- Do not add attribution lines to commit messages or pull request text.
- Each commit must compile and pass verification checks.

## Verification

Run these local checks before you submit a change:

- `bash .github/scripts/verify-repository-hygiene.sh`: Checks tracked files, module layout,
  and contract counts.
- `./gradlew --no-daemon clean verify`: Checks architecture rules, contract drift, script
  compilation, and distribution contents.
- `./gradlew --no-daemon test`: Runs all JUnit test suites across the workspace modules.
- `python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"`:
  Runs headless Ghidra function mutation checks on Linux x86-64 (requires `gcc` and `nm`).
- `bash .github/scripts/package-release.sh`: Verifies `version.txt`,
  `.release-please-manifest.json`, and JAR `Implementation-Version`, then builds the release
  archive and SHA-256 checksum in `build/release/`.

## Releases

- CI keeps the `verify -> release -> publish` job sequence without cross-job workflow artifacts.
- `release-please` creates a `v<version>` tag and stages a draft GitHub release
  (`"draft": true` and `"force-tag-creation": true` in `release-please-config.json`).
- `publish` gets `needs.release.outputs.sha` with `persist-credentials: false` and verifies
  `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft == true`,
  `.release-please-manifest.json`, and `version.txt` before Gradle runs.
- `publish` runs `package-release.sh`, `./gradlew --no-daemon test`, and
  `tests/function_mutation_regression.py` before asset upload.
- `publish` checks non-empty `.zip` and `.sha256` files, verifies `sha256sum -c`, uploads both
  assets with `gh release upload --clobber`, and promotes the draft release in place last with
  `gh api --method PATCH` and `-F draft=false`.
- A failure in `publish` leaves the GitHub release hidden as a draft until a maintainer reruns
  the failed jobs.
