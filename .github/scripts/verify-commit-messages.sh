#!/usr/bin/env bash
# Check commit messages and pull request titles against repository rules.
set -euo pipefail

export LC_COLLATE=C

allowed_types_pattern='^(build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test)$'
allowed_scopes_pattern='^(domain|wire|contracts|runtime|adapter|transport|websocket|mcp|launcher|docs|build|ci|test)$'
allowed_types_list='build, chore, ci, docs, feat, fix, perf, refactor, revert, style, test'
allowed_scopes_list='domain, wire, contracts, runtime, adapter, transport, websocket, mcp, launcher, docs, build, ci, test'

usage() {
  cat <<'EOF'
Usage: verify-commit-messages.sh [options]

Options:
  --commit-msg-file <path>  Validate a Git commit message file.
  --pr-title <title>        Validate a pull request title.
  --range <base..head>      Validate all commits in a Git revision range.
  --commit <rev>            Validate one Git commit.
  --main-push               Allow GitHub squash suffixes and trailers on main.
  -h, --help                Show this help text.
EOF
}

fail() {
  local context="$1"
  local reason="$2"
  shift 2
  printf 'commit message check failed (%s): %s\n' "$context" "$reason" >&2
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@" >&2
  fi
  exit 1
}

is_release_header() {
  local subject="$1"
  [[ "$subject" =~ ^chore\(main\):\ release\ [0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)*(\ \(#[0-9]+\))?$ ]]
}

is_footer_line() {
  local line="$1"
  if [[ "$line" =~ ^BREAKING\ CHANGE:\ .+$ ]] || [[ "$line" =~ ^BREAKING-CHANGE:\ .+$ ]]; then
    return 0
  fi
  if [[ "$line" =~ ^(Fixes|Closes|Resolves|Refs)(:\ |\ )#[0-9]+$ ]]; then
    return 0
  fi
  if [[ "$line" =~ ^[A-Za-z]+-[A-Za-z0-9-]+:\ .+$ ]]; then
    return 0
  fi
  return 1
}

is_squash_trailer_line() {
  local line="$1"
  [[ "$line" =~ ^([Cc][Oo]-[Aa][Uu][Tt][Hh][Oo][Rr][Ee][Dd]-[Bb][Yy]|[Ss][Ii][Gg][Nn][Ee][Dd]-[Oo][Ff][Ff]-[Bb][Yy]):\ .+$ ]]
}

is_attribution_line() {
  local line="$1"
  [[ "$line" =~ ^[Cc][Oo]-[Aa][Uu][Tt][Hh][Oo][Rr][Ee][Dd]-[Bb][Yy]: ]]
}

validate_header() {
  local context="$1"
  local header="$2"

  if [[ -z "$header" ]]; then
    fail "$context" "header is empty" \
      "Expected: <type>[(<scope>)][!]: <imperative summary>"
  fi

  if is_attribution_line "$header"; then
    fail "$context" "attribution lines such as Co-authored-by are not permitted" \
      "Header: $header"
  fi

  local header_length="${#header}"
  if [[ "$header_length" -gt 72 ]]; then
    fail "$context" "header has $header_length characters; maximum is 72" \
      "Header: $header"
  fi

  if [[ "$header" =~ [[:space:]]$ ]]; then
    fail "$context" "header must not have trailing spaces" \
      "Header: $header"
  fi

  if [[ ! "$header" =~ ^([^:[:space:]]+):\ (.+)$ ]]; then
    fail "$context" "header must obey Conventional Commits (<type>[(<scope>)][!]: <summary>)" \
      "Header: $header" \
      "Permitted types: $allowed_types_list" \
      "Permitted scopes: $allowed_scopes_list"
  fi

  local prefix="${BASH_REMATCH[1]}"
  local summary="${BASH_REMATCH[2]}"

  if [[ "$summary" =~ ^[[:space:]] ]]; then
    fail "$context" "put one space after the colon in the header" \
      "Header: $header"
  fi

  local raw_type="$prefix"
  local raw_scope=""
  local has_parens=0

  if [[ "$raw_type" == *! ]]; then
    raw_type="${raw_type%!}"
  fi

  if [[ "$raw_type" == *\(* ]]; then
    has_parens=1
    if [[ ! "$raw_type" =~ ^([^(]+)\(([^)]*)\)$ ]]; then
      fail "$context" "malformed type or scope in header" \
        "Header: $header" \
        "Expected: <type>[(<scope>)][!]: <summary>"
    fi
    raw_scope="${BASH_REMATCH[2]}"
    raw_type="${BASH_REMATCH[1]}"
  fi

  if [[ ! "$raw_type" =~ $allowed_types_pattern ]]; then
    fail "$context" "invalid commit type '$raw_type'" \
      "Header: $header" \
      "Permitted types: $allowed_types_list"
  fi

  if [[ "$has_parens" -eq 1 ]]; then
    if [[ -z "$raw_scope" ]]; then
      fail "$context" "scope must not be empty; omit parentheses when no scope applies" \
        "Header: $header"
    fi
    if [[ ! "$raw_scope" =~ $allowed_scopes_pattern ]]; then
      fail "$context" "invalid commit scope '$raw_scope'" \
        "Header: $header" \
        "Permitted scopes: $allowed_scopes_list"
    fi
  fi

  if [[ ! "$summary" =~ ^[a-z] ]]; then
    fail "$context" "summary must start with an imperative verb in lowercase letters" \
      "Header: $header"
  fi

  if [[ "$summary" == *. ]]; then
    fail "$context" "summary must not end with a period" \
      "Header: $header"
  fi
}

validate_pr_title() {
  local raw_title="${1%$'\r'}"
  if [[ -z "$raw_title" ]]; then
    fail "pull request title" "pull request title is empty"
  fi
  if [[ "$raw_title" == *$'\n'* ]]; then
    fail "pull request title" "pull request title must be a single line"
  fi
  if is_release_header "$raw_title"; then
    return 0
  fi
  validate_header "pull request title" "$raw_title"
}

validate_message() {
  local context="$1"
  local allow_squash="$2"
  local raw_message="$3"

  local lines=()
  local line=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    lines+=("$line")
  done < <(printf '%s\n' "$raw_message")

  local count="${#lines[@]}"
  while [[ "$count" -gt 0 && -z "${lines[$((count - 1))]}" ]]; do
    count=$((count - 1))
  done

  if [[ "$count" -eq 0 ]]; then
    fail "$context" "commit message is empty"
  fi

  local header="${lines[0]}"

  if [[ "$header" =~ ^Merge\  ]]; then
    return 0
  fi
  if is_release_header "$header"; then
    return 0
  fi

  local effective_header="$header"
  if [[ "$allow_squash" == "1" ]]; then
    effective_header="$(printf '%s' "$header" | sed -E 's/ \(#[0-9]+\)$//')"
    while [[ "$count" -gt 1 ]] && is_squash_trailer_line "${lines[$((count - 1))]}"; do
      count=$((count - 1))
    done
    while [[ "$count" -gt 0 && -z "${lines[$((count - 1))]}" ]]; do
      count=$((count - 1))
    done
  fi

  validate_header "$context" "$effective_header"

  local idx=1
  while [[ "$idx" -lt "$count" ]]; do
    local current="${lines[$idx]}"
    local line_number=$((idx + 1))
    if is_attribution_line "$current"; then
      fail "$context" "line $line_number contains forbidden attribution trailer" \
        "Line $line_number: $current"
    fi
    local current_length="${#current}"
    if [[ "$current_length" -gt 72 ]]; then
      fail "$context" "line $line_number has $current_length characters; maximum is 72" \
        "Line $line_number: $current"
    fi
    idx=$((idx + 1))
  done

  if [[ "$count" -eq 1 ]]; then
    return 0
  fi

  if [[ -n "${lines[1]}" ]]; then
    fail "$context" "put one blank line between the header and the body" \
      "Line 2: ${lines[1]}"
  fi

  if [[ "$count" -ge 3 && -z "${lines[2]}" ]]; then
    fail "$context" "put only one blank line after the header"
  fi

  local body_end="$count"
  local last_blank=-1
  idx=2
  while [[ "$idx" -lt "$count" ]]; do
    if [[ -z "${lines[$idx]}" ]]; then
      last_blank="$idx"
    fi
    idx=$((idx + 1))
  done

  if [[ "$last_blank" -eq -1 ]]; then
    local all_footers=1
    idx=2
    while [[ "$idx" -lt "$count" ]]; do
      if ! is_footer_line "${lines[$idx]}"; then
        all_footers=0
        break
      fi
      idx=$((idx + 1))
    done
    if [[ "$all_footers" -eq 1 ]]; then
      body_end=2
    fi
  else
    local trailing_are_footers=1
    idx=$((last_blank + 1))
    while [[ "$idx" -lt "$count" ]]; do
      if ! is_footer_line "${lines[$idx]}"; then
        trailing_are_footers=0
        break
      fi
      idx=$((idx + 1))
    done
    if [[ "$trailing_are_footers" -eq 1 ]]; then
      body_end="$last_blank"
    else
      fail "$context" "do not put blank lines in the commit body" \
        "Blank line at line $((last_blank + 1))"
    fi
  fi

  idx=2
  while [[ "$idx" -lt "$body_end" ]]; do
    local body_line="${lines[$idx]}"
    local body_line_num=$((idx + 1))
    if [[ -z "$body_line" ]]; then
      fail "$context" "do not put blank lines in the commit body" \
        "Blank line at line $body_line_num"
    fi
    if [[ "$body_line" =~ ^[[:space:]]+[-*+] ]]; then
      fail "$context" "do not use nested lists in the commit body" \
        "Line $body_line_num: $body_line"
    fi
    if [[ "$body_line" != -\ * ]]; then
      fail "$context" "write each body line as a '- ' list item on one line" \
        "Line $body_line_num: $body_line"
    fi
    local item_text="${body_line#- }"
    if [[ "$item_text" =~ ^[[:space:]] ]]; then
      fail "$context" "put one space after '-' in body list items" \
        "Line $body_line_num: $body_line"
    fi
    if [[ ! "$item_text" =~ ^[A-Z] ]]; then
      fail "$context" "start each body list item with a capital letter" \
        "Line $body_line_num: $body_line"
    fi
    idx=$((idx + 1))
  done
}

clean_commit_msg_file() {
  local msg_file="$1"
  [[ -f "$msg_file" ]] || fail "commit-msg" "message file does not exist: $msg_file"
  local cleaned=""
  local line=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    if [[ "$line" == "# ------------------------ >8 ------------------------" ]]; then
      break
    fi
    if [[ "$line" == \#* ]]; then
      continue
    fi
    cleaned+="${line}"$'\n'
  done <"$msg_file"
  printf '%s' "$cleaned"
}

check_commit() {
  local rev="$1"
  local allow_squash="$2"
  local sha
  sha="$(git rev-parse --verify "${rev}^{commit}" 2>/dev/null)" ||
    fail "$rev" "cannot resolve commit '$rev'"
  local short_sha="${sha:0:7}"

  local parents_line
  parents_line="$(git rev-list --parents -n 1 "$sha")"
  local parent_fields=()
  read -r -a parent_fields <<<"$parents_line"
  if [[ "${#parent_fields[@]}" -ge 3 ]]; then
    return 0
  fi

  local body
  body="$(git show -s --format=%B "$sha")"
  validate_message "commit $short_sha" "$allow_squash" "$body"
}

check_range() {
  local range="$1"
  local allow_squash="$2"
  local revs
  revs="$(git rev-list "$range" 2>/dev/null)" ||
    fail "$range" "cannot resolve commit range '$range'"
  local sha=""
  while IFS= read -r sha; do
    [[ -n "$sha" ]] || continue
    check_commit "$sha" "$allow_squash"
  done <<<"$revs"
}

commit_msg_file=""
has_pr_title_arg=0
pr_title_arg=""
range_arg=""
commit_arg=""
main_push=0

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --commit-msg-file)
      [[ "$#" -ge 2 ]] || fail "cli" "--commit-msg-file needs a file path"
      commit_msg_file="$2"
      shift 2
      ;;
    --pr-title)
      [[ "$#" -ge 2 ]] || fail "cli" "--pr-title needs a title value"
      has_pr_title_arg=1
      pr_title_arg="$2"
      shift 2
      ;;
    --range)
      [[ "$#" -ge 2 ]] || fail "cli" "--range needs a revision range"
      range_arg="$2"
      shift 2
      ;;
    --commit)
      [[ "$#" -ge 2 ]] || fail "cli" "--commit needs a revision"
      commit_arg="$2"
      shift 2
      ;;
    --main-push)
      main_push=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      fail "cli" "unknown argument '$1'"
      ;;
  esac
done

if [[ -n "$commit_msg_file" ]]; then
  cleaned_msg="$(clean_commit_msg_file "$commit_msg_file")"
  validate_message "commit-msg" "0" "$cleaned_msg"
  echo "commit message check passed"
  exit 0
fi

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

if [[ "$has_pr_title_arg" -eq 1 || -n "$range_arg" || -n "$commit_arg" ]]; then
  if [[ "$has_pr_title_arg" -eq 1 ]]; then
    validate_pr_title "$pr_title_arg"
  fi
  if [[ -n "$range_arg" ]]; then
    check_range "$range_arg" "$main_push"
  fi
  if [[ -n "$commit_arg" ]]; then
    check_commit "$commit_arg" "$main_push"
  fi
  echo "commit message check passed"
  exit 0
fi

event_name="${GITHUB_EVENT_NAME:-}"
if [[ "$event_name" == "pull_request" ]]; then
  validate_pr_title "${PR_TITLE:-}"
  [[ -n "${BASE_SHA:-}" && -n "${HEAD_SHA:-}" ]] ||
    fail "pull_request" "BASE_SHA and HEAD_SHA environment variables are required"
  check_range "${BASE_SHA}..${HEAD_SHA}" "0"
  echo "commit message check passed"
  exit 0
fi

ref_name="${GITHUB_REF:-$(git symbolic-ref -q HEAD || true)}"
if [[ "$ref_name" == "refs/heads/main" ]]; then
  main_push=1
fi
if [[ -n "${PR_TITLE:-}" ]]; then
  validate_pr_title "$PR_TITLE"
fi
check_commit "HEAD" "$main_push"
echo "commit message check passed"
