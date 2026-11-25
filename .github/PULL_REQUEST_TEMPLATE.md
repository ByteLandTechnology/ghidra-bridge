## Summary

<!-- State what changed. State why it changed. -->

## Compatibility

<!-- List affected methods, schemas, startup arguments, or behavior. -->

## Verification

- [ ] Configure Git hooks with `./gradlew --no-daemon installGitHooks` (also run by local `check` and `verify`).
- [ ] Run `bash .github/scripts/verify-repository-hygiene.sh`.
- [ ] Run `bash .github/scripts/verify-commit-messages.sh` and check that commits and the pull request title obey Conventional Commit rules (`AGENTS.md#commit-messages`).
- [ ] Run `./gradlew --no-daemon clean verify`.
- [ ] Regenerate contracts if the public interface changed.
- [ ] Check that the change has no build output or private data.

<!-- List any manual checks. -->

## Related issues

<!-- Example: Fixes #123. -->
