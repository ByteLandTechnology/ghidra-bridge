# AGENTS.md: rules for this repository

These rules apply to all persons and agents that change this repository.
CI checks compliance with these rules.

## English

- Use ASD-STE100 Simplified Technical English for all English text.
- This rule applies to this file, code comments, commit messages, and documentation.

## Modules and files

- Keep Ghidra API imports only in `modules/adapter` and `modules/launcher`.
- Keep `modules/domain` independent of transport and Ghidra types.
- Do not edit `docs/api.md`, `docs/asyncapi.yaml`, or `docs/mcp-tools.json` by hand.
- Run `./gradlew generateApiContracts` when a public method or schema changes.
- Do not commit build output, generated launcher scripts, zero-byte files, or duplicate files.
- Keep `docs/api.md` in sync with the 56 registered methods.

## Commit messages

- Obey Conventional Commits.
- Use no more than 72 characters on each line, including spaces and list markers.
- Use lowercase letters for the type and the scope.
- Start the summary with an imperative verb in lowercase letters.
- Do not put a period at the end of the summary.
- If you write a body, obey these rules:
  - Put one blank line between the header and the body.
  - Write the body as a list with `- ` before each item.
  - Start each item with a capital letter.
  - Put each item on one line. Do not put blank lines in the body.
  - Do not use nested lists.
- Do not add attribution lines to commit messages or pull request text.
- Each commit must compile and pass verification.

## Verification

Use JDK 21 and Ghidra 12.1 or newer with `GHIDRA_INSTALL_DIR` set.
Run these local checks before you submit a change:

```bash
bash .github/scripts/verify-repository-hygiene.sh
./gradlew --no-daemon clean verify
./gradlew --no-daemon test
python3 tests/function_mutation_regression.py "$GHIDRA_INSTALL_DIR/support/analyzeHeadless"
```

- `verify-repository-hygiene.sh`: Checks tracked files, generated paths, duplicates, and methods.
- `./gradlew --no-daemon clean verify`: Checks architecture boundaries, contracts, and scripts.
- `./gradlew --no-daemon test`: Runs all 14 JUnit test classes across the Gradle modules.
- `tests/function_mutation_regression.py`: Tests function mutations in headless Ghidra (`gcc`, `nm`).
- `bash .github/scripts/package-release.sh`: Validates `version.txt`,
  `.release-please-manifest.json`, and the JAR manifest, then builds the `.zip` and `.sha256` files.

## Releases

- `release-please-config.json` sets `"draft": true` and `"force-tag-creation": true`.
- On pushes to `main`, `release` runs first with dedicated concurrency (`cancel-in-progress: false`).
- When a release pull request merges, `release` creates the `v<version>` tag and a draft release.
- `verify` fetches `needs.release.outputs.sha || github.sha`, runs all checks once, and uploads
  `ghidra-bridge-<version>.zip` and `.sha256` workflow artifacts when `release_created == 'true'`.
- `publish` reuses the verified artifacts without a Java or Ghidra rebuild.
- `publish` verifies `HEAD`, the `v<version>` tag, the remote tag SHA, `isDraft`,
  `.release-please-manifest.json`, `version.txt`, non-empty files, and `sha256sum -c`.
- `publish` uploads both assets with `gh release upload --clobber` and patches `draft=false` last.
- If `verify` or `publish` fails, the GitHub Release remains a hidden draft while `Latest` points
  to the previous public release.
- Select "Re-run failed jobs" in GitHub Actions to overwrite workflow artifacts and partial draft
  assets before public promotion.
