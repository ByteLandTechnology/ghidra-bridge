## Summary

<!-- State what changed. State why it changed. -->

## Compatibility

<!-- List affected methods, schemas, startup arguments, or behavior. -->

## Verification

- [ ] Install hooks with `pre-commit install --install-hooks`.
- [ ] Run `pre-commit run --all-files`.
- [ ] Run `bash .github/scripts/verify-repository-hygiene.sh`.
- [ ] Run `./gradlew --no-daemon clean verify`.
- [ ] Obey the [commit message rules](../AGENTS.md#commit-messages) in commits and the pull request title.
- [ ] Regenerate contracts if the public interface changed.
- [ ] Check that the change has no build output or private data.

<!-- List any manual checks. -->

## Related issues

<!-- Example: Fixes #123. -->
