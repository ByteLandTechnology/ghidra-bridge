#!/usr/bin/env bash
# Build the release archive for the version in version.txt and .release-please-manifest.json.
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

file_version="$(<version.txt)"
file_version="${file_version#"${file_version%%[![:space:]]*}"}"
file_version="${file_version%"${file_version##*[![:space:]]}"}"
if [[ -z "$file_version" ]]; then
  echo "package-release: version.txt is empty" >&2
  exit 1
fi
version="${1-$file_version}"
if [[ -z "$version" ]]; then
  echo "package-release: release version must not be empty" >&2
  exit 1
fi
if [[ "$version" != "$file_version" ]]; then
  echo "package-release: version.txt has '$file_version', expected '$version'" >&2
  exit 1
fi

if command -v jq >/dev/null 2>&1; then
  release_manifest_version="$(jq -r '."." // empty' .release-please-manifest.json)"
else
  release_manifest_version="$(python3 -c 'import json; print(json.load(open(".release-please-manifest.json", encoding="utf-8")).get(".", "") or "")')"
fi
if [[ "$version" != "$release_manifest_version" ]]; then
  echo "package-release: .release-please-manifest.json has '$release_manifest_version', expected '$version'" >&2
  exit 1
fi

if [[ "${CI:-}" == "true" ]]; then
  ./gradlew --no-daemon --stacktrace -PreleaseVersion="$version" verify
else
  ./gradlew --no-daemon --stacktrace -PreleaseVersion="$version" clean verify
fi

jar="build/ghidra-script/ghidra-bridge.jar"
manifest_version="$(unzip -p "$jar" META-INF/MANIFEST.MF | tr -d '\r' | sed -n 's/^Implementation-Version: //p')"
if [[ "$manifest_version" != "$version" ]]; then
  echo "package-release: $jar has version '$manifest_version', expected '$version'" >&2
  exit 1
fi

name="ghidra-bridge-${version}"
release_dir="build/release"
stage="$release_dir/$name"
rm -rf "$release_dir"
mkdir -p "$stage"
cp build/ghidra-script/Bridge.java build/ghidra-script/GhidraMcp.java "$jar" "$stage/"
cp LICENSE README.md "$stage/"
find "$stage" -type d -exec chmod 0755 {} +
find "$stage" -type f -exec chmod 0644 {} +
TZ=UTC find "$stage" -depth -exec touch -t 198002010000.00 {} +

(
  cd "$release_dir"
  find "$name" -print | LC_ALL=C sort | TZ=UTC zip -q -X -@ "$name.zip"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$name.zip" > "$name.zip.sha256"
  else
    shasum -a 256 "$name.zip" > "$name.zip.sha256"
  fi
)
echo "package-release: created $release_dir/$name.zip"
