#!/usr/bin/env python3

"""Check release archive reproducibility across delayed and perturbed runs."""

import hashlib
import io
import os
import pathlib
import shutil
import subprocess
import tempfile
import time
import zipfile


EXPECTED_DOS_TIMESTAMP = (1980, 2, 1, 0, 0, 0)


def copy_working_tree(source_root: pathlib.Path, target_root: pathlib.Path) -> None:
    listed = subprocess.check_output(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        cwd=source_root,
    )
    for raw_entry in listed.split(b"\0"):
        if not raw_entry:
            continue
        relative = pathlib.Path(raw_entry.decode("utf-8"))
        source_path = source_root / relative
        if not source_path.is_file() and not source_path.is_symlink():
            continue
        destination = target_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination, follow_symlinks=False)
    subprocess.run(["git", "init", "-q"], cwd=target_root, check=True)


def run_package_script(
    repo_root: pathlib.Path,
    args: list[str],
    timezone: str,
    umask_octal: str,
    ci_mode: bool = False,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["TZ"] = timezone
    if ci_mode:
        env["CI"] = "true"
    else:
        env.pop("CI", None)
    command = f"umask {umask_octal} && exec bash .github/scripts/package-release.sh \"$@\""
    return subprocess.run(
        ["bash", "-c", command, "package-release", *args],
        cwd=repo_root,
        env=env,
        text=True,
        capture_output=True,
        check=check,
    )


def verify_archive(
    archive_path: pathlib.Path,
    checksum_path: pathlib.Path,
    version: str,
) -> tuple[bytes, str, str]:
    assert archive_path.is_file(), f"Missing archive: {archive_path}"
    assert checksum_path.is_file(), f"Missing checksum file: {checksum_path}"

    archive_bytes = archive_path.read_bytes()
    digest = hashlib.sha256(archive_bytes).hexdigest()
    checksum_text = checksum_path.read_text(encoding="utf-8")
    expected_checksum = f"{digest}  ghidra-bridge-{version}.zip\n"
    assert checksum_text == expected_checksum, (
        f"Unexpected checksum text: {checksum_text!r} != {expected_checksum!r}"
    )

    prefix = f"ghidra-bridge-{version}"
    expected_entries = [
        f"{prefix}/",
        f"{prefix}/Bridge.java",
        f"{prefix}/GhidraMcp.java",
        f"{prefix}/LICENSE",
        f"{prefix}/README.md",
        f"{prefix}/ghidra-bridge.jar",
    ]
    assert expected_entries == sorted(expected_entries)

    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        infos = archive.infolist()
        names = [info.filename for info in infos]
        assert names == expected_entries, f"Unexpected zip entry order: {names}"

        for info in infos:
            assert info.date_time == EXPECTED_DOS_TIMESTAMP, (
                f"Entry {info.filename} has DOS timestamp {info.date_time}, "
                f"expected {EXPECTED_DOS_TIMESTAMP}"
            )
            assert info.extra == b"", (
                f"Entry {info.filename} has extra metadata bytes: {info.extra!r}"
            )
            mode = (info.external_attr >> 16) & 0o777
            expected_mode = 0o755 if info.is_dir() else 0o644
            assert mode == expected_mode, (
                f"Entry {info.filename} has mode {oct(mode)}, expected {oct(expected_mode)}"
            )

        jar_bytes = archive.read(f"{prefix}/ghidra-bridge.jar")

    with zipfile.ZipFile(io.BytesIO(jar_bytes)) as jar:
        manifest = jar.read("META-INF/MANIFEST.MF").decode("utf-8").replace("\r\n", "\n")
    assert f"Implementation-Version: {version}\n" in manifest, (
        f"JAR manifest does not contain Implementation-Version {version}: {manifest!r}"
    )

    return archive_bytes, digest, checksum_text


def main() -> None:
    source_root = pathlib.Path(__file__).resolve().parents[1]
    base_version = (source_root / "version.txt").read_text(encoding="utf-8").strip()
    assert base_version, "Repository version.txt is empty"

    with tempfile.TemporaryDirectory(prefix="ghidra-release-repro-") as temp_dir:
        repo_root = pathlib.Path(temp_dir) / "repo"
        copy_working_tree(source_root, repo_root)
        version_file = repo_root / "version.txt"

        version_file.write_bytes(b"  \t\r\n \n")
        blank_result = run_package_script(
            repo_root, [], timezone="UTC", umask_octal="0022", check=False
        )
        assert blank_result.returncode != 0, "Expected blank version.txt to fail"

        version_file.write_bytes(f"  \t{base_version} \r\n\n".encode("utf-8"))
        mismatch = run_package_script(
            repo_root,
            ["0.0.0-mismatch"],
            timezone="UTC",
            umask_octal="0022",
            check=False,
        )
        assert mismatch.returncode != 0, "Expected version mismatch to fail"
        assert f"has '{base_version}', expected '0.0.0-mismatch'" in mismatch.stderr, (
            f"Unexpected mismatch error output: {mismatch.stderr!r}"
        )

        run_package_script(
            repo_root, [], timezone="EST5", umask_octal="0022", ci_mode=True
        )
        release_dir = repo_root / "build" / "release"
        archive_path = release_dir / f"ghidra-bridge-{base_version}.zip"
        checksum_path = release_dir / f"ghidra-bridge-{base_version}.zip.sha256"
        first_bytes, first_digest, first_checksum = verify_archive(
            archive_path, checksum_path, base_version
        )

        # Wait past the 2-second DOS zip timestamp granularity before the second build.
        time.sleep(2.1)

        version_file.write_bytes(f"{base_version}\n".encode("utf-8"))
        run_package_script(
            repo_root,
            [base_version],
            timezone="JST-9",
            umask_octal="0077",
            ci_mode=False,
        )
        second_bytes, second_digest, second_checksum = verify_archive(
            archive_path, checksum_path, base_version
        )

        assert first_digest == second_digest, (
            f"Zip SHA-256 changed across delayed runs: {first_digest} != {second_digest}"
        )
        assert first_bytes == second_bytes, "Zip bytes changed across delayed runs"
        assert first_checksum == second_checksum, "Checksum file changed across delayed runs"

    print(f"Release archive reproducibility checks passed ({first_digest})")


if __name__ == "__main__":
    main()
