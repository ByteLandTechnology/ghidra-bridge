#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bash .github/scripts/verify-formatting.sh [--fix]

Options:
  --fix       Format Java and Python files in place before verification.
  -h, --help  Print this help text.

Environment:
  GJF_CACHE_DIR  Directory for the cached google-java-format JAR.
                 Default: ${XDG_CACHE_HOME:-$HOME/.cache}/ghidra-bridge/google-java-format
EOF
}

fix_mode=false
for argument in "$@"; do
  case "$argument" in
    --fix)
      fix_mode=true
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      printf 'formatting check failed: unknown option: %s\n' "$argument" >&2
      usage >&2
      exit 1
      ;;
  esac
done

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

fail() {
  local summary="$1"
  shift
  printf 'formatting check failed: %s\n' "$summary" >&2
  if [[ "$#" -gt 0 ]]; then
    printf '%s\n' "$@" >&2
  fi
  exit 1
}

verify_sha256() {
  local file_path="$1"
  local expected_sha256="$2"
  if command -v sha256sum >/dev/null 2>&1; then
    echo "${expected_sha256}  ${file_path}" | sha256sum -c - >/dev/null 2>&1
  elif command -v shasum >/dev/null 2>&1; then
    echo "${expected_sha256}  ${file_path}" | shasum -a 256 -c - >/dev/null 2>&1
  else
    fail "sha256sum or shasum is required"
  fi
}

gjf_version="2.0.0"
gjf_sha256="c78feb48c549fa7114b7ea11db3b456808f7b371ffe84e6643a44dd2f9588639"
gjf_jar_name="google-java-format-${gjf_version}-all-deps.jar"
gjf_url="https://github.com/google/google-java-format/releases/download/v${gjf_version}/${gjf_jar_name}"
default_cache_root="${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}"
cache_dir="${GJF_CACHE_DIR:-${default_cache_root}/ghidra-bridge/google-java-format}"
gjf_jar="${cache_dir}/${gjf_jar_name}"

temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

# Download the formatter JAR when it is absent from the local cache.
if [[ ! -f "$gjf_jar" ]]; then
  command -v curl >/dev/null 2>&1 || fail "curl is required to download ${gjf_jar_name}"
  mkdir -p "$cache_dir"
  downloaded_jar="${temporary_directory}/${gjf_jar_name}"
  curl -sSL --fail -o "$downloaded_jar" "$gjf_url" || fail "cannot download ${gjf_jar_name}"
  verify_sha256 "$downloaded_jar" "$gjf_sha256" || fail "checksum mismatch for ${gjf_jar_name}"
  mv "$downloaded_jar" "$gjf_jar"
fi

# Verify the SHA-256 checksum before execution.
verify_sha256 "$gjf_jar" "$gjf_sha256" || fail "cached ${gjf_jar_name} failed SHA-256 check"

command -v java >/dev/null 2>&1 || fail "java is required"
command -v python3 >/dev/null 2>&1 || fail "python3 is required"
command -v ruff >/dev/null 2>&1 || fail "ruff is required"

java_files=()
while IFS= read -r -d '' candidate; do
  if [[ -f "$candidate" ]]; then
    java_files+=("$candidate")
  fi
done < <(git ls-files -z '*.java')

if [[ "${#java_files[@]}" -gt 0 ]]; then
  if [[ "$fix_mode" == "true" ]]; then
    java -jar "$gjf_jar" --replace "${java_files[@]}"
  fi

  if ! unformatted_java="$(
    java -jar "$gjf_jar" --dry-run --set-exit-if-changed "${java_files[@]}"
  )"; then
    fail "Java files need formatting (run bash .github/scripts/verify-formatting.sh --fix)" \
      "$unformatted_java"
  fi

  overlong_java="$(
    python3 - "${java_files[@]}" <<'PY'
import pathlib
import sys

limit = 100
violations = []
for raw_path in sys.argv[1:]:
    path = pathlib.Path(raw_path)
    with path.open("r", encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            content = line.rstrip("\r\n")
            width = len(content)
            if width > limit:
                violations.append(f"  {raw_path}:{number} ({width} > {limit})")
if violations:
    print("\n".join(violations))
PY
  )"
  [[ -z "$overlong_java" ]] || fail "Java lines exceed 100 characters" "$overlong_java"
fi

ruff_rules="E,F,W,I,EXE"
if [[ "$fix_mode" == "true" ]]; then
  ruff check --no-cache --select "$ruff_rules" --fix-only tests/
  ruff format --no-cache tests/
fi

ruff check --no-cache --select "$ruff_rules" tests/
ruff format --no-cache --check tests/

echo "formatting check passed"
