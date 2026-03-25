#!/usr/bin/env python3
"""Sign Basilisk release metadata and artifacts with Ed25519."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


REPO_ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = REPO_ROOT / "build"


def _resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (REPO_ROOT / path)


def load_private_key() -> ed25519.Ed25519PrivateKey:
    env_key = os.environ.get("BASILISK_RELEASE_SIGNING_KEY")
    if env_key:
        key_bytes = base64.b64decode(env_key)
        return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)

    key_file = os.environ.get("BASILISK_RELEASE_SIGNING_KEY_FILE")
    key_path = _resolve_path(key_file or BUILD_DIR / "release-signing.key")
    if key_path.exists():
        key_bytes = key_path.read_bytes()
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key_bytes)
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)


def sign_files(files: list[Path]) -> dict:
    private_key = load_private_key()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    bundle = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "algorithm": "ed25519",
        "public_key": public_key.hex(),
        "signatures": [],
    }
    for path in files:
        payload = path.read_bytes()
        sig = private_key.sign(payload)
        bundle["signatures"].append(
            {
                "path": str(path.relative_to(REPO_ROOT)),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "signature": base64.b64encode(sig).decode("ascii"),
            }
        )
    return bundle


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign Basilisk release metadata")
    parser.add_argument(
        "files",
        nargs="*",
        default=[
            "build/release-manifest.json",
            "build/sbom.json",
            "build/provenance.json",
        ],
    )
    args = parser.parse_args()
    files = [_resolve_path(item) for item in args.files]
    for path in files:
        if not path.exists():
            raise SystemExit(f"Missing file to sign: {path}")
    bundle = sign_files(files)
    BUILD_DIR.mkdir(parents=True, exist_ok=True)
    out = BUILD_DIR / "release-signatures.json"
    out.write_text(json.dumps(bundle, indent=2), "utf-8")
    (BUILD_DIR / "release-public.key").write_text(bundle["public_key"], "utf-8")
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
