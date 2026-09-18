from __future__ import annotations

import json
from pathlib import Path

from .types import AttackSpec, EVIDENCE_CLASSES


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ATTACK_REGISTER_PATH = REPOSITORY_ROOT / "spec" / "attack-register.json"


def load_attack_register(path: Path = ATTACK_REGISTER_PATH) -> list[AttackSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    attacks = [AttackSpec.from_mapping(item) for item in raw["attacks"]]
    ids = [item.attack_id for item in attacks]
    if ids != list(range(1, 60)):
        raise ValueError(f"attack register must contain exactly IDs 1..59, got {ids}")
    if len({item.title for item in attacks}) != 59:
        raise ValueError("attack titles must be unique")
    invalid_classes = {
        item.evidence_class for item in attacks if item.evidence_class not in EVIDENCE_CLASSES
    }
    if invalid_classes:
        raise ValueError(f"invalid evidence classes: {sorted(invalid_classes)}")
    return attacks


def evidence_class_counts(attacks: list[AttackSpec] | None = None) -> dict[str, int]:
    rows = attacks if attacks is not None else load_attack_register()
    counts = {name: 0 for name in sorted(EVIDENCE_CLASSES)}
    for item in rows:
        counts[item.evidence_class] += 1
    return counts
