## Summary

<!-- State what changed. State why it changed. -->

## Compatibility

<!-- List affected methods, schemas, startup arguments, or behavior. -->

## Verification

- [ ] Run `./gradlew --no-daemon installGitHooks`.
- [ ] Run `./gradlew --no-daemon clean verify`.
- [ ] Run `bash .github/scripts/verify-repository-hygiene.sh`.
- [ ] Run `bash .github/scripts/verify-commit-messages.sh`.
- [ ] Check that the pull request title and commits obey `AGENTS.md`.
- [ ] Regenerate contracts if the public interface changed.
- [ ] Check that the change has no build output or private data.

<!-- List any manual checks. -->

## Related issues

<!-- Example: Fixes #123. -->
