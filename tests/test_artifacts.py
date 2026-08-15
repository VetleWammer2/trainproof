from __future__ import annotations

from copy import deepcopy
from pathlib import Path

from trainproof.artifacts import (
    SOURCE_EXCLUSION_POLICY,
    source_manifest,
    validate_source_manifest,
    verify_source_manifest,
)


def test_source_manifest_excludes_generated_and_secret_trees(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    (tmp_path / ".ruff_cache").mkdir()
    (tmp_path / ".ruff_cache" / "cache-entry").write_text("generated", encoding="utf-8")
    (tmp_path / "zk" / "build").mkdir(parents=True)
    (tmp_path / "zk" / "build" / "verification_key.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (tmp_path / "zk" / "demo-run" / "private" / "keys").mkdir(parents=True)
    (tmp_path / "zk" / "demo-run" / "private" / "keys" / "secret.json").write_text(
        "{}\n", encoding="utf-8"
    )
    (tmp_path / "src" / "package.egg-info").mkdir()
    (tmp_path / "src" / "package.egg-info" / "PKG-INFO").write_text(
        "generated", encoding="utf-8"
    )
    (tmp_path / "demo-run" / "private").mkdir(parents=True)
    (tmp_path / "demo-run" / "private" / "key.json").write_text(
        "secret", encoding="utf-8"
    )
    manifest = source_manifest(tmp_path)
    assert [entry["path"] for entry in manifest["files"]] == ["src/app.py"]
    assert manifest["exclusion_policy"] == SOURCE_EXCLUSION_POLICY
    assert validate_source_manifest(manifest)
    assert verify_source_manifest(tmp_path, manifest)


def test_source_manifest_rejects_bundle_selected_exclusions(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    manifest = source_manifest(tmp_path)
    manifest["excluded_paths"] = ["src"]
    assert not validate_source_manifest(manifest)
    assert not verify_source_manifest(tmp_path, manifest)


def test_source_verification_compares_git_metadata(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('ok')\n", encoding="utf-8")
    manifest = source_manifest(tmp_path)
    tampered = deepcopy(manifest)
    tampered["git"] = {
        "tool_available": True,
        "is_work_tree": True,
        "commit": None,
        "dirty": False,
    }
    assert validate_source_manifest(tampered)
    assert not verify_source_manifest(tmp_path, tampered)
