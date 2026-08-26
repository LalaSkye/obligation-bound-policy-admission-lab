from __future__ import annotations

import argparse
import hashlib
import json
import platform
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXCLUDED_PARTS = {".git", "__pycache__", ".pytest_cache", ".venv", "build", "dist"}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def selected_files(output: Path) -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or path == output:
            continue
        relative = path.relative_to(ROOT)
        if any(part in EXCLUDED_PARTS for part in relative.parts):
            continue
        if path.suffix in {".pyc", ".pyo"}:
            continue
        files.append(path)
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output if args.output.is_absolute() else ROOT / args.output
    records = [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(path.read_bytes()),
            "size": path.stat().st_size,
        }
        for path in selected_files(output)
    ]
    tree_material = "\n".join(f"{row['sha256']}  {row['path']}" for row in records).encode()
    report_path = ROOT / "artifacts" / "test-run-v0.6.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    manifest = {
        "schema_version": "1.0",
        "candidate": "Obligation-Bound Policy Admission Lab v0.6",
        "status": "PUBLIC_RELEASE",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "python": platform.python_version(),
        "source_tree_digest": sha256_bytes(tree_material),
        "files": records,
        "test_report": {
            "path": "artifacts/test-run-v0.6.json",
            "sha256": sha256_bytes(report_path.read_bytes()),
            "summary": report["summary"],
        },
        "source_candidate_sha256": "3af7e1abbaa8378d56f59799484ee0ae030c4a88bdbf87895e781a8d13301468",
        "claim_ceiling": "Local bounded-harness evidence only; not safety, legitimacy, production-readiness or global non-bypassability.",
        "publication": "https://github.com/LalaSkye/obligation-bound-policy-admission-lab",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"source_tree_digest": manifest["source_tree_digest"], "files": len(records), "tests": report["summary"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
