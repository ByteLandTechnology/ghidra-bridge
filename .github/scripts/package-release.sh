#!/usr/bin/env bash
# Build the release archive for the version in version.txt.
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

mode="auto"
if [[ "${1:-}" == "--reuse-build" ]]; then
  mode="reuse"
  shift
elif [[ "${1:-}" == "--clean" ]]; then
  mode="clean"
  shift
fi

file_version="$(tr -d '\r\n' < version.txt)"
version="${1:-$file_version}"
if [[ "$version" != "$file_version" ]]; then
  echo "package-release: version.txt has '$file_version', expected '$version'" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  release_manifest_version="$(jq -r '."."' .release-please-manifest.json)"
else
  release_manifest_version="$(python3 -c 'import json; print(json.load(open(".release-please-manifest.json"))["."])')"
fi
if [[ "$version" != "$release_manifest_version" ]]; then
  echo "package-release: .release-please-manifest.json has '$release_manifest_version', expected '$version'" >&2
  exit 1
fi

jar="build/ghidra-script/ghidra-bridge.jar"
bridge_script="build/ghidra-script/Bridge.java"
mcp_script="build/ghidra-script/GhidraMcp.java"

read_jar_version() {
  unzip -p "$jar" META-INF/MANIFEST.MF | tr -d '\r' | sed -n 's/^Implementation-Version: //p'
}

has_verified_build() {
  [[ -s "$jar" && -s "$bridge_script" && -s "$mcp_script" ]] &&
    [[ -s "build/compiled-scripts/Bridge.class" && -s "build/compiled-scripts/GhidraMcp.class" ]] &&
    [[ "$(read_jar_version)" == "$version" ]]
}

if [[ "$mode" == "reuse" ]]; then
  if [[ ! -s "$jar" || ! -s "$bridge_script" || ! -s "$mcp_script" ]]; then
    echo "package-release: verified build files are missing under build/ghidra-script/" >&2
    exit 1
  fi
elif [[ "$mode" == "clean" ]] || ! has_verified_build; then
  ./gradlew --no-daemon -PreleaseVersion="$version" clean verify test
fi

manifest_version="$(read_jar_version)"
if [[ "$manifest_version" != "$version" ]]; then
  echo "package-release: $jar has version '$manifest_version', expected '$version'" >&2
  exit 1
fi

name="ghidra-bridge-${version}"
release_dir="build/release"
stage="$release_dir/$name"
rm -rf "$release_dir"
mkdir -p "$stage"
cp "$bridge_script" "$mcp_script" "$jar" "$stage/"
cp LICENSE README.md "$stage/"

(
  cd "$release_dir"
  zip -q -r -X "$name.zip" "$name"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$name.zip" > "$name.zip.sha256"
    sha256sum -c "$name.zip.sha256" >/dev/null
  else
    shasum -a 256 "$name.zip" > "$name.zip.sha256"
    shasum -a 256 -c "$name.zip.sha256" >/dev/null
  fi
  test -s "$name.zip"
  test -s "$name.zip.sha256"
)
echo "package-release: created $release_dir/$name.zip"
