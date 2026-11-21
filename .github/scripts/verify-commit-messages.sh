#!/usr/bin/env bash
# Verify Conventional Commit messages and pull request titles.
set -euo pipefail

caller_pwd="$PWD"
repository_root="$(git rev-parse --show-toplevel)"

allowed_types="build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test"
allowed_scopes="domain, wire, contracts, runtime, adapter, transport, websocket, mcp, launcher, docs, build, ci, test"

type_regex='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)$'
scope_regex='^(domain|wire|contracts|runtime|adapter|transport|websocket|mcp|launcher|docs|build|ci|test)$'
header_regex='^([^(:!]+)(\(([^)]*)\))?(!)?: (.*)$'
merge_regex='^Merge '
release_regex='^chore\(main\): release( .*)?$'
lowercase_start_regex='^[a-z]'
trailing_space_regex='[[:space:]]$'
leading_space_regex='^[[:space:]]'
indented_bullet_regex='^[[:space:]]+- '
bullet_prefix_regex='^- '
bullet_item_regex='^- [A-Z]'
attribution_regex='^[Cc][Oo]-[Aa][Uu][Tt][Hh][Oo][Rr][Ee][Dd]-[Bb][Yy]:'
footer_regex='^(BREAKING CHANGE: .+|BREAKING-CHANGE: .+|[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]+: .+|[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9-]+ #.+|(Fixes|Closes|Resolves|Refs)(: | #).+)$'

usage() {
  cat <<'EOF'
Usage: verify-commit-messages.sh [options]

Options:
  --file <path>     Validate a commit message file (strips '#' comment lines).
  --commit <rev>    Validate a single Git commit (default: HEAD).
  --range <a..b>    Validate all Git commits in a revision range.
  --title <title>   Validate a pull request title.
  -h, --help        Show this help text.
EOF
}

fail_check() {
  local context="$1"
  local reason="$2"
  printf 'commit message check failed (%s): %s\n' "$context" "$reason" >&2
  printf '  format: <type>[optional (<scope>)][optional !]: <summary>\n' >&2
  printf '  example: fix(wire): reject unknown fields\n' >&2
  printf '  types: %s\n' "$allowed_types" >&2
  printf '  scopes: %s\n' "$allowed_scopes" >&2
  printf '  rules: <= 72 chars per line; lowercase verb summary without period; "- " list body\n' >&2
  return 1
}

resolve_path() {
  local raw_path="$1"
  if [[ "$raw_path" == /* ]]; then
    printf '%s\n' "$raw_path"
  else
    printf '%s/%s\n' "$caller_pwd" "$raw_path"
  fi
}

validate_header_line() {
  local context="$1"
  local header="$2"

  if [[ ${#header} -gt 72 ]]; then
    fail_check "$context" "line 1 has ${#header} characters; maximum is 72"
    return 1
  fi

  if [[ "$header" =~ $attribution_regex ]]; then
    fail_check "$context" "do not add Co-Authored-By attribution lines"
    return 1
  fi

  if [[ ! "$header" =~ $header_regex ]]; then
    fail_check "$context" "header does not obey Conventional Commits syntax"
    return 1
  fi

  local commit_type="${BASH_REMATCH[1]}"
  local scope_wrapper="${BASH_REMATCH[2]}"
  local commit_scope="${BASH_REMATCH[3]}"
  local summary="${BASH_REMATCH[5]}"

  if [[ ! "$commit_type" =~ $type_regex ]]; then
    fail_check "$context" "invalid type '$commit_type'"
    return 1
  fi

  if [[ -n "$scope_wrapper" && ! "$commit_scope" =~ $scope_regex ]]; then
    fail_check "$context" "invalid scope '$commit_scope'"
    return 1
  fi

  if [[ -z "$summary" || "$summary" =~ $leading_space_regex ]]; then
    fail_check "$context" "summary after ': ' must not be empty or start with a space"
    return 1
  fi

  if [[ ! "$summary" =~ $lowercase_start_regex ]]; then
    fail_check "$context" "summary must start with an imperative verb in lowercase letters"
    return 1
  fi

  if [[ "$summary" == *. ]]; then
    fail_check "$context" "summary must not end with a period"
    return 1
  fi

  if [[ "$summary" =~ $trailing_space_regex ]]; then
    fail_check "$context" "summary must not end with spaces"
    return 1
  fi

  return 0
}

validate_message_text() {
  local context="$1"
  local mode="$2"
  local raw_text="$3"

  local lines=()
  local line=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$mode" == "file" ]]; then
      if [[ "$line" == "# ------------------------ >8 ------------------------" ]]; then
        break
      fi
      if [[ "$line" == \#* ]]; then
        continue
      fi
    fi
    lines+=("$line")
  done <<<"$raw_text"

  # Remove blank lines at the end of the message.
  while [[ ${#lines[@]} -gt 0 ]]; do
    local last_index=$(( ${#lines[@]} - 1 ))
    if [[ -z "${lines[$last_index]}" ]]; then
      unset "lines[$last_index]"
    else
      break
    fi
  done

  local count=${#lines[@]}
  if [[ "$count" -eq 0 ]]; then
    fail_check "$context" "message must not be empty"
    return 1
  fi

  local header="${lines[0]}"
  if [[ -z "$header" ]]; then
    fail_check "$context" "line 1 must be the commit header, not a blank line"
    return 1
  fi

  # Exempt Merge commits and release-please commits.
  if [[ "$header" =~ $merge_regex || "$header" =~ $release_regex ]]; then
    return 0
  fi

  if [[ "$mode" == "title" && "$count" -gt 1 ]]; then
    fail_check "$context" "pull request title must be a single line"
    return 1
  fi

  validate_header_line "$context" "$header" || return 1

  if [[ "$count" -eq 1 ]]; then
    return 0
  fi

  local index=1
  while [[ "$index" -lt "$count" ]]; do
    local current="${lines[$index]}"
    local line_number=$(( index + 1 ))
    if [[ ${#current} -gt 72 ]]; then
      fail_check "$context" "line $line_number has ${#current} characters; maximum is 72"
      return 1
    fi
    if [[ "$current" =~ $attribution_regex ]]; then
      fail_check "$context" "do not add Co-Authored-By attribution on line $line_number"
      return 1
    fi
    index=$(( index + 1 ))
  done

  if [[ -n "${lines[1]}" ]]; then
    fail_check "$context" "line 2 must be blank between the header and the body"
    return 1
  fi

  if [[ -z "${lines[2]}" ]]; then
    fail_check "$context" "put only one blank line after the header"
    return 1
  fi

  local section="body"
  if [[ "${lines[2]}" =~ $footer_regex ]]; then
    section="footer"
  fi

  index=2
  while [[ "$index" -lt "$count" ]]; do
    local current="${lines[$index]}"
    local line_number=$(( index + 1 ))

    if [[ "$section" == "body" ]]; then
      if [[ -z "$current" ]]; then
        local next_index=$(( index + 1 ))
        if [[ "$next_index" -lt "$count" && "${lines[$next_index]}" =~ $footer_regex ]]; then
          section="footer"
          index=$(( index + 1 ))
          continue
        fi
        fail_check "$context" "do not put blank lines in the commit body (line $line_number)"
        return 1
      fi

      if [[ "$current" =~ $indented_bullet_regex ]]; then
        fail_check "$context" "do not use nested lists in the commit body (line $line_number)"
        return 1
      fi

      if [[ ! "$current" =~ $bullet_prefix_regex ]]; then
        fail_check "$context" "body line $line_number must start with '- '"
        return 1
      fi

      if [[ ! "$current" =~ $bullet_item_regex ]]; then
        fail_check "$context" "body item on line $line_number must start with a capital letter after '- '"
        return 1
      fi
    else
      if [[ -z "$current" ]]; then
        local next_index=$(( index + 1 ))
        if [[ "$next_index" -ge "$count" || ! "${lines[$next_index]}" =~ $footer_regex ]]; then
          fail_check "$context" "blank line $line_number in footers must precede a valid footer"
          return 1
        fi
      fi
    fi

    index=$(( index + 1 ))
  done

  return 0
}

validate_file() {
  local target_file="$1"
  if [[ ! -f "$target_file" ]]; then
    printf 'commit message check failed: file not found: %s\n' "$target_file" >&2
    return 1
  fi
  local content=""
  content="$(cat "$target_file")"
  validate_message_text "$target_file" "file" "$content"
}

validate_commit() {
  local rev="$1"
  if ! git rev-parse --verify "${rev}^{commit}" >/dev/null 2>&1; then
    printf 'commit message check failed: unknown commit revision: %s\n' "$rev" >&2
    return 1
  fi
  local short_sha=""
  short_sha="$(git rev-parse --short "${rev}^{commit}")"
  local content=""
  content="$(git show -s --format=%B "$rev")"
  validate_message_text "commit $short_sha" "commit" "$content"
}

validate_range() {
  local range="$1"
  if [[ -z "$range" || "$range" == ".." || "$range" == "..." ]]; then
    printf 'commit message check failed: invalid commit range: %s\n' "$range" >&2
    return 1
  fi
  local commits=""
  if ! commits="$(git rev-list --reverse "$range" 2>/dev/null)"; then
    printf 'commit message check failed: cannot resolve commit range: %s\n' "$range" >&2
    return 1
  fi
  if [[ -z "$commits" ]]; then
    echo "commit message check passed (0 commits in range $range)"
    return 0
  fi
  local status=0
  local sha=""
  while IFS= read -r sha; do
    [[ -n "$sha" ]] || continue
    if ! validate_commit "$sha"; then
      status=1
    fi
  done <<<"$commits"
  return "$status"
}

cd "$repository_root"

if [[ "$#" -eq 0 ]]; then
  validate_commit "HEAD"
  echo "commit message check passed"
  exit 0
fi

overall_status=0
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --file)
      if [[ "$#" -lt 2 ]]; then
        echo "commit message check failed: --file requires a path argument" >&2
        exit 1
      fi
      resolved_file="$(resolve_path "$2")"
      validate_file "$resolved_file" || overall_status=1
      shift 2
      ;;
    --commit)
      if [[ "$#" -lt 2 ]]; then
        echo "commit message check failed: --commit requires a revision argument" >&2
        exit 1
      fi
      validate_commit "$2" || overall_status=1
      shift 2
      ;;
    --range)
      if [[ "$#" -lt 2 ]]; then
        echo "commit message check failed: --range requires a range argument" >&2
        exit 1
      fi
      validate_range "$2" || overall_status=1
      shift 2
      ;;
    --title)
      if [[ "$#" -lt 2 ]]; then
        echo "commit message check failed: --title requires a title argument" >&2
        exit 1
      fi
      if [[ "$2" == *$'\n'* || "$2" == *$'\r'* ]]; then
        fail_check "pull request title" "pull request title must be a single line" || overall_status=1
      else
        validate_message_text "pull request title" "title" "$2" || overall_status=1
      fi
      shift 2
      ;;
    --*)
      printf 'commit message check failed: unknown option: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
    *)
      candidate_file="$(resolve_path "$1")"
      if [[ -f "$candidate_file" ]]; then
        validate_file "$candidate_file" || overall_status=1
      elif [[ "$1" == *..* ]]; then
        validate_range "$1" || overall_status=1
      elif git rev-parse --verify "${1}^{commit}" >/dev/null 2>&1; then
        validate_commit "$1" || overall_status=1
      else
        printf 'commit message check failed: invalid argument: %s\n' "$1" >&2
        usage >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ "$overall_status" -ne 0 ]]; then
  exit 1
fi

echo "commit message check passed"
