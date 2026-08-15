"""Content-addressed source and checkpoint artifacts."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from .canonical import hash_bytes, hash_object

SOURCE_MANIFEST_SCHEME = "canonical-source-tree-sha256/v1"
SOURCE_EXCLUSION_POLICY = "trainproof-fixed-source-exclusions/v3"

# These exclusions are protocol policy, not values supplied by the bundle being
# verified. Changing them requires a new exclusion-policy identifier.
_EXCLUDED_ANYWHERE = {
    ".git",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
    ".venv",
}
_EXCLUDED_TOP_LEVEL = {"demo-run", "tampered-run", "build", "tools", "dist"}
_EXCLUDED_PREFIXES = {("zk", "build"), ("zk", "demo-run")}
_EXCLUDED_SUFFIXES = {".pyc", ".wtns", ".zkey", ".ptau"}


def source_path_is_excluded(relative: Path) -> bool:
    return (
        (bool(relative.parts) and relative.parts[0] in _EXCLUDED_TOP_LEVEL)
        or any(relative.parts[: len(prefix)] == prefix for prefix in _EXCLUDED_PREFIXES)
        or any(
            part in _EXCLUDED_ANYWHERE or part.endswith(".egg-info")
            for part in relative.parts
        )
        or relative.suffix in _EXCLUDED_SUFFIXES
    )


def _included_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if source_path_is_excluded(relative):
            continue
        yield path


def _git_metadata(base: Path) -> dict[str, Any]:
    executable = shutil.which("git")
    if executable is None:
        return {
            "tool_available": False,
            "is_work_tree": None,
            "commit": None,
            "dirty": None,
        }

    probe = subprocess.run(
        [executable, "-C", str(base), "rev-parse", "--is-inside-work-tree"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if probe.returncode != 0 or probe.stdout.strip() != "true":
        return {
            "tool_available": True,
            "is_work_tree": False,
            "commit": None,
            "dirty": None,
        }

    commit_result = subprocess.run(
        [executable, "-C", str(base), "rev-parse", "--verify", "HEAD"],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    commit = commit_result.stdout.strip() if commit_result.returncode == 0 else None
    status_result = subprocess.run(
        [
            executable,
            "-C",
            str(base),
            "status",
            "--porcelain",
            "--untracked-files=all",
            "--",
            ".",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if status_result.returncode != 0:
        raise ValueError(
            f"could not inspect Git worktree: {status_result.stderr.strip()}"
        )
    return {
        "tool_available": True,
        "is_work_tree": True,
        "commit": commit,
        "dirty": bool(status_result.stdout.strip()),
    }


def source_manifest(root: str | Path) -> dict[str, Any]:
    base = Path(root).resolve()
    if not base.is_dir():
        raise ValueError(f"source root is not a directory: {base}")
    entries: list[dict[str, Any]] = []
    for path in _included_files(base):
        relative = path.relative_to(base).as_posix()
        payload = path.read_bytes()
        entries.append(
            {
                "path": relative,
                "size": len(payload),
                "digest": hash_bytes("source-file/v1", payload).hex(),
            }
        )
    return {
        "scheme": SOURCE_MANIFEST_SCHEME,
        "exclusion_policy": SOURCE_EXCLUSION_POLICY,
        "root": hash_object("source-tree/v1", entries).hex(),
        "file_count": len(entries),
        "files": entries,
        "git": _git_metadata(base),
    }


def _canonical_hex(value: Any, byte_lengths: set[int]) -> bool:
    if not isinstance(value, str):
        return False
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        return False
    return len(raw) in byte_lengths and raw.hex() == value


def validate_source_manifest(value: Any) -> bool:
    """Validate a manifest without trusting it to choose omitted paths."""

    if not isinstance(value, dict) or set(value) != {
        "scheme",
        "exclusion_policy",
        "root",
        "file_count",
        "files",
        "git",
    }:
        return False
    if (
        value.get("scheme") != SOURCE_MANIFEST_SCHEME
        or value.get("exclusion_policy") != SOURCE_EXCLUSION_POLICY
        or not _canonical_hex(value.get("root"), {32})
    ):
        return False
    files = value.get("files")
    if not isinstance(files, list) or value.get("file_count") != len(files):
        return False
    paths: list[str] = []
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {"path", "size", "digest"}:
            return False
        path_text = entry.get("path")
        size = entry.get("size")
        if not isinstance(path_text, str) or not path_text or "\\" in path_text:
            return False
        path = PurePosixPath(path_text)
        if (
            path.is_absolute()
            or path.as_posix() != path_text
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            return False
        if source_path_is_excluded(Path(*path.parts)):
            return False
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            return False
        if not _canonical_hex(entry.get("digest"), {32}):
            return False
        paths.append(path_text)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        return False
    if value["root"] != hash_object("source-tree/v1", files).hex():
        return False

    git = value.get("git")
    if not isinstance(git, dict) or set(git) != {
        "tool_available",
        "is_work_tree",
        "commit",
        "dirty",
    }:
        return False
    tool_available = git.get("tool_available")
    is_work_tree = git.get("is_work_tree")
    commit = git.get("commit")
    dirty = git.get("dirty")
    if not isinstance(tool_available, bool):
        return False
    if not tool_available:
        return is_work_tree is None and commit is None and dirty is None
    if not isinstance(is_work_tree, bool):
        return False
    if not is_work_tree:
        return commit is None and dirty is None
    if dirty is not True and dirty is not False:
        return False
    return commit is None or _canonical_hex(commit, {20, 32})


def verify_source_manifest(root: str | Path, expected: dict[str, Any]) -> bool:
    if not validate_source_manifest(expected):
        return False
    try:
        actual = source_manifest(root)
    except (OSError, ValueError, subprocess.SubprocessError):
        return False
    return actual == expected
