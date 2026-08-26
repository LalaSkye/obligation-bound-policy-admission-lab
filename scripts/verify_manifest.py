from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    path = args.manifest if args.manifest.is_absolute() else ROOT / args.manifest
    manifest = json.loads(path.read_text(encoding="utf-8"))
    expected = {row["path"]: row for row in manifest["files"]}
    current: dict[str, dict[str, object]] = {}
    for candidate in ROOT.rglob("*"):
        if not candidate.is_file() or candidate == path:
            continue
        relative = candidate.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in relative.parts) or candidate.suffix in {".pyc", ".pyo"}:
            continue
        current[relative.as_posix()] = {
            "path": relative.as_posix(),
            "sha256": sha256_bytes(candidate.read_bytes()),
            "size": candidate.stat().st_size,
        }
    if current != expected:
        missing = sorted(set(expected) - set(current))
        extra = sorted(set(current) - set(expected))
        changed = sorted(key for key in set(current) & set(expected) if current[key] != expected[key])
        print(json.dumps({"verified": False, "missing": missing, "extra": extra, "changed": changed}, indent=2))
        return 1
    ordered = [current[key] for key in sorted(current)]
    material = "\n".join(f"{row['sha256']}  {row['path']}" for row in ordered).encode()
    calculated = sha256_bytes(material)
    verified = calculated == manifest["source_tree_digest"]
    print(json.dumps({"verified": verified, "source_tree_digest": calculated, "files": len(ordered)}, indent=2))
    return 0 if verified else 1


if __name__ == "__main__":
    raise SystemExit(main())
