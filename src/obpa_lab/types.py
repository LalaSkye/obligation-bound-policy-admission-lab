from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class AdmissionVerdict(str, Enum):
    ALLOW = "ALLOW"
    HOLD = "HOLD"
    DENY = "DENY"


class OperationalResult(str, Enum):
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    COMMITTED = "COMMITTED"
    TRANSACTION_CONFLICT = "TRANSACTION_CONFLICT"
    TRANSACTION_FAILURE = "TRANSACTION_FAILURE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    STATE_INDETERMINATE = "STATE_INDETERMINATE"
    COMMIT_PRECONDITION_CONFLICT = "COMMIT_PRECONDITION_CONFLICT"
    HALTED = "HALTED"


class EngineMode(str, Enum):
    READY = "READY"
    ACTIVE = "ACTIVE"
    HALTED = "HALTED"
    QUARANTINED = "QUARANTINED"


class EvidenceState(str, Enum):
    POSITIVELY_ESTABLISHED = "POSITIVELY_ESTABLISHED"
    POSITIVELY_INVALID = "POSITIVELY_INVALID"
    ABSENCE_OBSERVED = "ABSENCE_OBSERVED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_STALE = "SOURCE_STALE"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    WRONG_SOURCE = "WRONG_SOURCE"
    WRONG_NAMESPACE = "WRONG_NAMESPACE"
    CONFLICT = "CONFLICT"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class PredicateTrace:
    predicate: str
    established: bool
    reason: str
    evidence_state: EvidenceState | None = None


EVIDENCE_CLASSES = frozenset({
    "ENGINE_DERIVED",
    "META_TEST",
    "OUT_OF_SCOPE",
    "UNIMPLEMENTED_CANDIDATE",
})


@dataclass(frozen=True)
class Outcome:
    admission: AdmissionVerdict
    operational: OperationalResult = OperationalResult.NOT_ATTEMPTED
    reason: str = ""
    failed_predicate: str = ""
    evidence_state: EvidenceState | None = None
    activated: bool = False
    committed: bool = False
    consequence_count: int = 0
    engine_mode: EngineMode = EngineMode.READY
    traces: list[PredicateTrace] = field(default_factory=list)
    sequence: list[str] = field(default_factory=list)
    operation_results: list[OperationalResult] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def trace_for(self, predicate: str) -> PredicateTrace | None:
        return next((t for t in self.traces if t.predicate == predicate), None)


@dataclass(frozen=True)
class AttackSpec:
    attack_id: int
    title: str
    source_range: str
    expected_admission: tuple[AdmissionVerdict, ...]
    expected_operational: tuple[OperationalResult, ...]
    expected_reason: str
    expected_predicate: str
    activated: bool
    committed: bool
    engine_modes: tuple[EngineMode, ...]
    oracle_mode: str = "MATCH"
    evidence_class: str = "ENGINE_DERIVED"

    @classmethod
    def from_mapping(cls, raw: dict[str, Any]) -> "AttackSpec":
        def many(enum_type: type[Enum], name: str) -> tuple[Any, ...]:
            value = raw.get(name, [])
            if isinstance(value, str):
                value = [value]
            return tuple(enum_type(v) for v in value)

        return cls(
            attack_id=int(raw["id"]),
            title=str(raw["title"]),
            source_range=str(raw["source_range"]),
            expected_admission=many(AdmissionVerdict, "expected_admission"),
            expected_operational=many(OperationalResult, "expected_operational"),
            expected_reason=str(raw.get("expected_reason", "")),
            expected_predicate=str(raw.get("expected_predicate", "")),
            activated=bool(raw.get("activated", False)),
            committed=bool(raw.get("committed", False)),
            engine_modes=many(EngineMode, "engine_modes"),
            oracle_mode=str(raw.get("oracle_mode", "MATCH")),
            evidence_class=str(raw.get("evidence_class", "ENGINE_DERIVED")),
        )


@dataclass(frozen=True)
class OracleEvaluation:
    passed: bool
    mismatches: tuple[str, ...]


def evaluate_oracle(spec: AttackSpec, outcome: Outcome) -> OracleEvaluation:
    mismatches: list[str] = []
    if spec.expected_admission and outcome.admission not in spec.expected_admission:
        mismatches.append(f"admission={outcome.admission.value}")
    if spec.expected_operational and outcome.operational not in spec.expected_operational:
        mismatches.append(f"operational={outcome.operational.value}")
    if spec.expected_reason and outcome.reason != spec.expected_reason:
        mismatches.append(f"reason={outcome.reason}")
    if spec.expected_predicate and outcome.failed_predicate != spec.expected_predicate:
        mismatches.append(f"predicate={outcome.failed_predicate}")
    if outcome.activated != spec.activated:
        mismatches.append(f"activated={outcome.activated}")
    if outcome.committed != spec.committed:
        mismatches.append(f"committed={outcome.committed}")
    if spec.engine_modes and outcome.engine_mode not in spec.engine_modes:
        mismatches.append(f"engine_mode={outcome.engine_mode.value}")
    matched = not mismatches
    if spec.oracle_mode == "REJECT_WRONG_REASON":
        return OracleEvaluation(passed=not matched and outcome.admission in spec.expected_admission, mismatches=tuple(mismatches))
    return OracleEvaluation(passed=matched, mismatches=tuple(mismatches))


def enum_values(items: Iterable[Enum]) -> list[str]:
    return [item.value for item in items]
