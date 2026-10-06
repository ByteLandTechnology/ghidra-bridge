#!/usr/bin/env bash
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT
inventory_file="$temporary_directory/inventory"
hash_file="$temporary_directory/hashes"

# Check tracked files. Ignore files that CI downloads or builds.
git ls-files --cached | sort -u >"$inventory_file"

fail() {
  local summary="$1"
  shift
  printf 'repository hygiene check failed: %s\n' "$summary" >&2
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@" >&2
  fi
  exit 1
}

ignored_tracked="$(git ls-files -ci --exclude-standard || true)"
[[ -z "$ignored_tracked" ]] || fail "ignored files are tracked" "$ignored_tracked"

unexpected_files="$(
  grep -E '(^|/)(build|out|bin)/|(^|/)\.gradle/|(^|/)\.idea/|(^|/)\.vscode/|(^|/)\.DS_Store$|\.iml$' "$inventory_file" || true
)"
[[ -z "$unexpected_files" ]] || fail "generated or local files are candidates for commit" "$unexpected_files"

legacy_gradle="$(grep -E '(^|/)(build|settings)\.gradle\.kts$' "$inventory_file" || true)"
[[ -z "$legacy_gradle" ]] || fail "obsolete Kotlin Gradle files remain" "$legacy_gradle"

root_sources="$(grep -E '^src/' "$inventory_file" || true)"
[[ -z "$root_sources" ]] || fail "the root project must not own source files" "$root_sources"

templates="$(grep -E '^modules/launcher/src/main/templates/[^/]+\.template$' "$inventory_file" || true)"
template_count="$(printf '%s\n' "$templates" | sed '/^$/d' | wc -l | tr -d ' ')"
[[ "$template_count" == "1" ]] || fail "expected one launcher template, found $template_count"

launcher_sources="$(grep -E '(^|/)(Bridge|GhidraMcp)\.java$' "$inventory_file" || true)"
[[ -z "$launcher_sources" ]] || fail "generated launcher scripts must not be committed" "$launcher_sources"

markdown_files=(README*.md)
while IFS= read -r -d '' candidate; do
  markdown_files+=("$candidate")
done < <(find docs -type f -name '*.md' -print0)
stale_protocol="$(grep -lE ':tooling:contract-docs|distribution/src/main/templates' "${markdown_files[@]}" || true)"
[[ -z "$stale_protocol" ]] || fail "stale protocol or build paths remain" "$stale_protocol"

zero_byte_files=""
: >"$hash_file"
while IFS= read -r candidate; do
  [[ -n "$candidate" && -f "$candidate" && ! -L "$candidate" ]] || continue
  if [[ ! -s "$candidate" ]]; then
    zero_byte_files+="${zero_byte_files:+$'\n'}$candidate"
    continue
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest="$(sha256sum "./$candidate" | awk '{print $1}')"
  else
    digest="$(shasum -a 256 "./$candidate" | awk '{print $1}')"
  fi
  printf '%s\t%s\n' "$digest" "$candidate" >>"$hash_file"
done <"$inventory_file"
[[ -z "$zero_byte_files" ]] || fail "zero-byte files are candidates for commit" "$zero_byte_files"

duplicate_files="$(
  sort -k1,1 "$hash_file" |
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
    cut -f2- || true
)"
[[ -z "$duplicate_files" ]] || fail "exact duplicate files are candidates for commit" "$duplicate_files"

method_count="$(grep -Ec '^\| `[^`]+` \|' docs/api.md || true)"
[[ "$method_count" == "53" ]] || fail "docs/api.md documents $method_count methods; expected 53"

echo "repository hygiene check passed"
