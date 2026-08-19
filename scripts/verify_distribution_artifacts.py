#!/usr/bin/env python3
"""Build and verify TrustWeave wheel and source distributions in temporary local environments."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "trustweave"
REQUIRED_PACKAGE_FILES = frozenset({"__init__.py", "__main__.py", "cli.py", "py.typed"})


def _run(command: list[str], *, cwd: Path) -> str:
    """Run one local build or isolated-install command with captured diagnostics."""

    completed = subprocess.run(command, cwd=cwd, check=False, capture_output=True, text=True)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Local command failed ({' '.join(command)}): {detail}")
    return completed.stdout


def _git_status() -> str:
    """Read repository status without modifying the checkout."""

    return _run(["git", "status", "--porcelain"], cwd=ROOT)


def _project_version() -> str:
    """Read the authoritative package version without importing the working tree package."""

    for line in (ROOT / "pyproject.toml").read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.removeprefix("version = ").strip().strip('"')
    raise ValueError("pyproject.toml has no project version")


def _assert_safe_archive_names(names: list[str], label: str) -> None:
    """Reject archive members that could escape a clean extraction directory."""

    unsafe = [name for name in names if Path(name).is_absolute() or ".." in Path(name).parts]
    if unsafe:
        raise ValueError(f"{label} contains unsafe archive members: {unsafe}")


def _assert_wheel_contract(wheel_path: Path, version: str) -> None:
    """Require the wheel to contain the module entry point and packaged schemas."""

    with zipfile.ZipFile(wheel_path) as archive:
        names = archive.namelist()
        _assert_safe_archive_names(names, "wheel")
        package_prefix = f"{PACKAGE}/"
        package_files = {
            name.removeprefix(package_prefix) for name in names if name.startswith(package_prefix)
        }
        missing = REQUIRED_PACKAGE_FILES - package_files
        if missing:
            raise ValueError(f"wheel is missing required package files: {sorted(missing)}")
        if not any(
            name.startswith(f"{PACKAGE}/schemas/") and name.endswith(".schema.json")
            for name in names
        ):
            raise ValueError("wheel is missing packaged JSON schemas")
        metadata_names = [name for name in names if name.endswith(".dist-info/METADATA")]
        if len(metadata_names) != 1:
            raise ValueError("wheel must contain exactly one dist-info METADATA file")
        metadata = archive.read(metadata_names[0]).decode("utf-8")
        if f"Name: {PACKAGE}" not in metadata or f"Version: {version}" not in metadata:
            raise ValueError("wheel METADATA does not match the project name and version")


def _assert_sdist_contract(sdist_path: Path, version: str) -> None:
    """Require the source distribution to contain installable package and build sources."""

    prefix = f"{PACKAGE}-{version}/"
    with tarfile.open(sdist_path, "r:gz") as archive:
        names = archive.getnames()
        _assert_safe_archive_names(names, "source distribution")
        required = {
            f"{prefix}pyproject.toml",
            f"{prefix}src/{PACKAGE}/__init__.py",
            f"{prefix}src/{PACKAGE}/__main__.py",
            f"{prefix}src/{PACKAGE}/py.typed",
        }
        missing = required - set(names)
        if missing:
            raise ValueError(f"source distribution is missing required files: {sorted(missing)}")
        if not any(
            name.startswith(f"{prefix}src/{PACKAGE}/schemas/") and name.endswith(".schema.json")
            for name in names
        ):
            raise ValueError("source distribution is missing packaged JSON schemas")


def _resource_check_script(path: Path) -> Path:
    """Write one isolated runtime resource check without adding files to the checkout."""

    script = path / "check_installed_resources.py"
    script.write_text(
        "from importlib.resources import files\n"
        "from trustweave import __version__\n"
        "resources = files('trustweave').joinpath('schemas')\n"
        "assert any(item.name.endswith('.schema.json') for item in resources.iterdir())\n"
        "print(__version__)\n",
        encoding="utf-8",
    )
    return script


def _assert_isolated_install(artifact_path: Path, version: str, directory: Path) -> None:
    """Install one local artifact in a fresh venv and verify both supported CLI entry points."""

    directory.mkdir(parents=True, exist_ok=False)
    venv = directory / "venv"
    _run([sys.executable, "-m", "venv", str(venv)], cwd=directory)
    python = venv / "bin" / "python"
    console = venv / "bin" / PACKAGE
    _run([str(python), "-m", "pip", "install", "--no-deps", str(artifact_path)], cwd=directory)
    for command in (
        [str(console), "--version"],
        [str(python), "-m", PACKAGE, "--version"],
        [str(python), "-m", PACKAGE, "--help"],
        [str(python), str(_resource_check_script(directory))],
    ):
        output = _run(command, cwd=directory)
        if (
            command[-1] == "--version" or command[1:4] == ["-m", PACKAGE, "--version"]
        ) and output.strip() != version:
            raise ValueError(
                f"isolated artifact CLI returned {output.strip()!r}, expected {version!r}"
            )


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    """Parse the minimum inputs needed for repeatable local distribution assurance."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Test-only escape hatch; otherwise require a clean repository working tree.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Build, inspect, and clean-install local distributions without release publication."""

    args = _parse_args(argv)
    initial_status = _git_status()
    if initial_status and not args.allow_dirty:
        print("Distribution verification requires a clean repository working tree")
        return 2
    version = _project_version()
    try:
        with tempfile.TemporaryDirectory(prefix=".trustweave-dist-", dir=ROOT) as temporary:
            workspace = Path(temporary)
            dist = workspace / "dist"
            _run([sys.executable, "-m", "build", "--outdir", str(dist)], cwd=ROOT)
            wheels = sorted(dist.glob("*.whl"))
            sdists = sorted(dist.glob("*.tar.gz"))
            if len(wheels) != 1 or len(sdists) != 1:
                raise ValueError("expected exactly one wheel and one source distribution")
            wheel, sdist = wheels[0], sdists[0]
            _assert_wheel_contract(wheel, version)
            _assert_sdist_contract(sdist, version)
            _assert_isolated_install(wheel, version, workspace / "wheel-install")
            _assert_isolated_install(sdist, version, workspace / "sdist-install")
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, tarfile.TarError) as error:
        print(f"Distribution verification failed: {error}")
        return 1
    if _git_status() != initial_status:
        print("Distribution verification changed the repository working tree")
        return 1
    print(
        "Distribution verification passed: wheel and source distribution are packaged and "
        "installable."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
