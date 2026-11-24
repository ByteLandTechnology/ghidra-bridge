#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
inventory_nul_file="$temporary_directory/inventory_nul"
inventory_file="$temporary_directory/inventory"
ignored_nul_file="$temporary_directory/ignored_nul"
hash_file="$temporary_directory/hashes"

fail() {
  local summary="$1"
  shift
  printf 'repository hygiene check failed: %s\n' "$summary" >&2
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@" >&2
  fi
  exit 1
}

grep_nomatch_ok() {
  local status=0
  grep "$@" || status=$?
  if [[ "$status" -le 1 ]]; then
    return 0
  fi
  return "$status"
}

# Check tracked files. Ignore files that CI downloads or builds.
git ls-files --cached -z >"$inventory_nul_file"
tr '\0' '\n' <"$inventory_nul_file" | LC_ALL=C sort -u >"$inventory_file"

git ls-files -ci --exclude-standard -z >"$ignored_nul_file"
if [[ -s "$ignored_nul_file" ]]; then
  ignored_tracked="$(tr '\0' '\n' <"$ignored_nul_file")"
  fail "ignored files are tracked" "$ignored_tracked"
fi

unexpected_files="$(
  grep_nomatch_ok -E '(^|/)(build|out|bin|__pycache__)/|(^|/)\.gradle/|(^|/)\.idea/|(^|/)\.vscode/|(^|/)\.DS_Store$|\.iml$|\.py[cod]$' "$inventory_file"
)"
[[ -z "$unexpected_files" ]] || fail "generated or local files are candidates for commit" "$unexpected_files"

legacy_gradle="$(grep_nomatch_ok -E '(^|/)(build|settings)\.gradle\.kts$' "$inventory_file")"
[[ -z "$legacy_gradle" ]] || fail "obsolete Kotlin Gradle files remain" "$legacy_gradle"

root_sources="$(grep_nomatch_ok -E '^src/' "$inventory_file")"
[[ -z "$root_sources" ]] || fail "the root project must not own source files" "$root_sources"

templates="$(grep_nomatch_ok -E '^modules/launcher/src/main/templates/[^/]+\.template$' "$inventory_file")"
template_count="$(printf '%s\n' "$templates" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$template_count" == "1" ]] || fail "expected one launcher template, found $template_count"

launcher_sources="$(grep_nomatch_ok -E '(^|/)(Bridge|GhidraMcp)\.java$' "$inventory_file")"
[[ -z "$launcher_sources" ]] || fail "generated launcher scripts must not be committed" "$launcher_sources"

markdown_files=(README*.md)
if [[ -d docs ]]; then
  find docs -type f -name '*.md' -print0 >"$temporary_directory/docs_markdown"
  while IFS= read -r -d '' candidate; do
    markdown_files+=("$candidate")
  done <"$temporary_directory/docs_markdown"
fi

if [[ "${#markdown_files[@]}" -gt 0 ]]; then
  stale_protocol="$(grep_nomatch_ok -lE ':tooling:contract-docs|distribution/src/main/templates' "${markdown_files[@]}")"
  [[ -z "$stale_protocol" ]] || fail "stale protocol or build paths remain" "$stale_protocol"
fi

hygiene_scan_files=("${markdown_files[@]}")
if [[ -d .github ]]; then
  find .github -type f -print0 >"$temporary_directory/github_files"
  while IFS= read -r -d '' candidate; do
    hygiene_scan_files+=("$candidate")
  done <"$temporary_directory/github_files"
fi

if [[ "${#hygiene_scan_files[@]}" -gt 0 ]]; then
  mcp_domains="$(
    jq -er '
      .tools
      | if length == 0 then error("docs/mcp-tools.json defines zero tools") else . end
      | map(.name | capture("^ghidra_(?<domain>[a-z][a-z0-9_]*)$").domain)
      | unique
      | join("|")
    ' docs/mcp-tools.json
  )"
  retired_urls="$(grep_nomatch_ok -IlE '[b]yteland-app' "${hygiene_scan_files[@]}")"
  [[ -z "$retired_urls" ]] || fail "retired organization URLs remain" "$retired_urls"

  dotted_tools="$(
    grep_nomatch_ok -IlE "(^|[^[:alnum:]_])ghidra\\.(${mcp_domains})([^[:alnum:]_]|$)" "${hygiene_scan_files[@]}"
  )"
  [[ -z "$dotted_tools" ]] || fail "retired dotted MCP tool names remain" "$dotted_tools"
fi

zero_byte_files=""
: >"$hash_file"
while IFS= read -r -d '' candidate; do
  [[ -n "$candidate" && -f "$candidate" && ! -L "$candidate" ]] || continue
  if [[ ! -s "$candidate" ]]; then
    zero_byte_files+="${zero_byte_files:+$'\n'}$candidate"
    continue
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum <"./$candidate" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 <"./$candidate" | awk '{print $1}')"
  fi
  printf '%s\t%s\n' "$digest" "$candidate" >>"$hash_file"
done <"$inventory_nul_file"
[[ -z "$zero_byte_files" ]] || fail "zero-byte files are candidates for commit" "$zero_byte_files"

duplicate_files="$(
  LC_ALL=C sort -k1,1 "$hash_file" |
    awk -F '\t' '
      $1 == previous_hash {
        if (!printing_group) print previous_line
        print
        printing_group = 1
        next
      }
      {
        previous_hash = $1
        previous_line = $0
        printing_group = 0
      }
    ' |
    cut -f2-
)"
[[ -z "$duplicate_files" ]] || fail "exact duplicate files are candidates for commit" "$duplicate_files"

backtick=$'\140'
method_count="$(grep_nomatch_ok -Ec "^\\| ${backtick}[^${backtick}]+${backtick} \\|" docs/api.md)"
[[ "$method_count" == "56" ]] || fail "docs/api.md documents $method_count methods; expected 56"

echo "repository hygiene check passed"
