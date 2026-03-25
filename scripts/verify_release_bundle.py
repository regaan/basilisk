#!/usr/bin/env python3
"""Verify Basilisk release metadata signatures."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519


REPO_ROOT = Path(__file__).resolve().parents[1]


def _resolve_path(value: str | Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (REPO_ROOT / path)


def verify_bundle(bundle_path: Path) -> None:
    bundle = json.loads(bundle_path.read_text("utf-8"))
    public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(bundle["public_key"]))
    for entry in bundle.get("signatures", []):
        path = _resolve_path(entry["path"])
        payload = path.read_bytes()
        signature = base64.b64decode(entry["signature"])
        expected_sha = entry.get("sha256")
        actual_sha = hashlib.sha256(payload).hexdigest()
        if expected_sha and expected_sha != actual_sha:
            raise ValueError(f"SHA256 mismatch for {path}: expected {expected_sha}, got {actual_sha}")
        public_key.verify(signature, payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Basilisk release metadata signatures")
    parser.add_argument("bundle", nargs="?", default="build/release-signatures.json")
    args = parser.parse_args()
    bundle_path = _resolve_path(args.bundle)
    verify_bundle(bundle_path)
    print(f"Verified {bundle_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
