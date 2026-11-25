## Summary

<!-- State what changed. State why it changed. -->

## Compatibility

<!-- List affected methods, schemas, startup arguments, or behavior. -->

## Verification

- [ ] Run `pre-commit run --all-files` and `bash .github/scripts/verify-repository-hygiene.sh`.
- [ ] Check the pull request title and commits with `pre-commit run --hook-stage commit-msg --commit-msg-filename .git/COMMIT_EDITMSG` ([commit message rules](AGENTS.md#commit-messages)).
- [ ] Run `./gradlew --no-daemon clean verify`.
- [ ] Regenerate contracts if the public interface changed.
- [ ] Check that the change has no build output or private data.

<!-- List any manual checks. -->

## Related issues

<!-- Example: Fixes #123. -->
