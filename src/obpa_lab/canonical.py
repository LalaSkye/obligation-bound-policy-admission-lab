from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def normalise(value: Any) -> Any:
    """Return a deterministic JSON-compatible representation."""
    if dataclasses.is_dataclass(value):
        value = dataclasses.asdict(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise ValueError("naive datetime is not canonical")
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, bytes):
        return {"$bytes_hex": value.hex()}
    if isinstance(value, dict):
        return {str(k): normalise(v) for k, v in sorted(value.items(), key=lambda kv: str(kv[0]))}
    if isinstance(value, (list, tuple)):
        return [normalise(v) for v in value]
    if isinstance(value, (set, frozenset)):
        return sorted((normalise(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        normalise(value),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def bytes_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
