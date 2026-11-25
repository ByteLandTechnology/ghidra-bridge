#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
message_file="$temporary_directory/COMMIT_EDITMSG"

check_message() {
  local label="$1"
  local allow_squash="$2"
  local raw_message="$3"
  local action

  action="$(
    RAW_MESSAGE="$raw_message" \
      python3 .github/scripts/verify-commit-message.py --prepare-ci "$allow_squash" "$message_file"
  )"

  if [[ "$action" == "EXEMPT" ]]; then
    printf 'Skipping exempt %s\n' "$label"
    return 0
  fi

  printf 'Validating %s\n' "$label"
  pre-commit run --hook-stage commit-msg --commit-msg-filename "$message_file"
}

event_name="${EVENT_NAME:-push}"
ref_name="${REF_NAME:-}"

if [[ "$event_name" == "pull_request" ]]; then
  if [[ -z "${BASE_SHA:-}" || -z "${HEAD_SHA:-}" ]]; then
    echo "commit check failed: BASE_SHA and HEAD_SHA are required for pull_request events" >&2
    exit 1
  fi

  check_message "pull request title" "false" "${PR_TITLE:-}"

  while IFS= read -r commit_sha; do
    [[ -n "$commit_sha" ]] || continue
    commit_message="$(git log -1 --format=%B "$commit_sha")"
    check_message "commit $commit_sha" "false" "$commit_message"
  done < <(git rev-list "${BASE_SHA}..${HEAD_SHA}")
else
  allow_squash="false"
  if [[ "$ref_name" == "refs/heads/main" || "$ref_name" == refs/tags/* ]]; then
    allow_squash="true"
  fi
  head_message="$(git log -1 --format=%B HEAD)"
  check_message "HEAD commit" "$allow_squash" "$head_message"
fi
