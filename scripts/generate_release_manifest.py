#!/usr/bin/env python3
"""Generate lightweight release metadata for Basilisk packaging workflows."""

from __future__ import annotations

import hashlib
import json
import os
import argparse
from datetime import datetime, timezone
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = ROOT / "build"
PYPROJECT = ROOT / "pyproject.toml"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_manifest_files() -> list[Path]:
    include_roots = [
        ROOT / "basilisk",
        ROOT / "desktop" / "src",
        ROOT / "native",
        ROOT / "pyproject.toml",
        ROOT / "requirements.txt",
        ROOT / "basilisk-backend.spec",
    ]
    files: list[Path] = []
    for item in include_roots:
        if item.is_file():
            files.append(item)
            continue
        if item.exists():
            for path in item.rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts and "node_modules" not in path.parts:
                    files.append(path)
    return sorted(files)


def build_sbom(pyproject: dict) -> dict:
    project = pyproject.get("project", {})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "name": project.get("name", "basilisk-ai"),
        "version": project.get("version", "unknown"),
        "dependencies": project.get("dependencies", []),
        "optional_dependencies": project.get("optional-dependencies", {}),
    }


def build_provenance(pyproject: dict) -> dict:
    project = pyproject.get("project", {})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "builder": {
            "user": os.environ.get("USER", "unknown"),
            "cwd": str(ROOT),
            "python": os.environ.get("VIRTUAL_ENV", ""),
            "github_run_id": os.environ.get("GITHUB_RUN_ID", ""),
            "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            "github_sha": os.environ.get("GITHUB_SHA", ""),
            "github_ref": os.environ.get("GITHUB_REF", ""),
        },
        "subject": {
            "name": project.get("name", "basilisk-ai"),
            "version": project.get("version", "unknown"),
        },
        "inputs": {
            "pyproject": sha256_file(PYPROJECT),
            "requirements": sha256_file(ROOT / "requirements.txt"),
            "backend_spec": sha256_file(ROOT / "basilisk-backend.spec"),
        },
    }


def iter_release_assets(artifact_root: Path | None) -> list[dict[str, str | int]]:
    if artifact_root is None or not artifact_root.exists():
        return []

    patterns = ("*.exe", "*.dmg", "*.AppImage", "*.pacman", "*.deb", "*.rpm", "*.zip", "*.tar.gz")
    assets: list[dict[str, str | int]] = []
    seen: set[Path] = set()
    for pattern in patterns:
        for path in artifact_root.rglob(pattern):
            if path.is_file() and path not in seen:
                seen.add(path)
                assets.append(
                    {
                        "path": str(path.relative_to(ROOT)),
                        "sha256": sha256_file(path),
                        "size": path.stat().st_size,
                    }
                )
    return sorted(assets, key=lambda item: str(item["path"]))


def load_build_metadata(build_metadata_root: Path | None) -> list[dict]:
    if build_metadata_root is None or not build_metadata_root.exists():
        return []
    data: list[dict] = []
    for path in sorted(build_metadata_root.rglob("basilisk-build-metadata.json")):
        data.append(json.loads(path.read_text("utf-8")))
    return data


def build_manifest(
    pyproject: dict,
    artifact_root: Path | None = None,
    build_metadata_root: Path | None = None,
) -> dict:
    project = pyproject.get("project", {})
    files = iter_manifest_files()
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "name": project.get("name", "basilisk-ai"),
        "version": project.get("version", "unknown"),
        "build_trust": load_build_metadata(build_metadata_root),
        "artifacts": iter_release_assets(artifact_root),
        "files": [
            {
                "path": str(path.relative_to(ROOT)),
                "sha256": sha256_file(path),
                "size": path.stat().st_size,
            }
            for path in files
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Basilisk release metadata")
    parser.add_argument(
        "--artifact-root",
        default="",
        help="Optional directory containing packaged release artifacts to hash into the manifest.",
    )
    parser.add_argument(
        "--build-metadata-root",
        default="",
        help="Optional directory containing per-platform build metadata JSON files.",
    )
    args = parser.parse_args()

    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    pyproject = tomllib.loads(PYPROJECT.read_text("utf-8"))
    artifact_root = (ROOT / args.artifact_root) if args.artifact_root else None
    build_metadata_root = (ROOT / args.build_metadata_root) if args.build_metadata_root else None

    manifest = build_manifest(
        pyproject,
        artifact_root=artifact_root,
        build_metadata_root=build_metadata_root,
    )
    sbom = build_sbom(pyproject)
    provenance = build_provenance(pyproject)

    (BUILD_DIR / "release-manifest.json").write_text(json.dumps(manifest, indent=2), "utf-8")
    (BUILD_DIR / "sbom.json").write_text(json.dumps(sbom, indent=2), "utf-8")
    (BUILD_DIR / "provenance.json").write_text(json.dumps(provenance, indent=2), "utf-8")
    print("Wrote build/release-manifest.json, build/sbom.json, build/provenance.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
