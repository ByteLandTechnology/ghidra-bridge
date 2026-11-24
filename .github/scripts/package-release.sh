#!/usr/bin/env bash
# Build the release archive for the version in version.txt.
set -euo pipefail

repository_root="$(git rev-parse --show-toplevel)"
cd "$repository_root"

file_version="$(cat version.txt)"
version="${1:-$file_version}"
if [[ "$version" != "$file_version" ]]; then
  echo "package-release: version.txt has '$file_version', expected '$version'" >&2
  exit 1
fi

./gradlew --no-daemon -PreleaseVersion="$version" clean verify

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

(cd "$release_dir" && zip -q -r -X "$name.zip" "$name" && sha256sum "$name.zip" > "$name.zip.sha256")
echo "package-release: created $release_dir/$name.zip"
