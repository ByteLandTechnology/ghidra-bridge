#!/usr/bin/env bash
# Run the typed repository rule verifier in modules/contracts.
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"
exec ./gradlew --no-daemon verifyRepositoryRules
