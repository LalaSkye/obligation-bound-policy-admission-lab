from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .canonical import digest
from .types import EvidenceState
from .types import AdmissionVerdict, OperationalResult


@dataclass(frozen=True)
class TimeWindow:
    valid_from: datetime
    valid_until: datetime

    def contains(self, at: datetime) -> bool:
        return self.valid_from <= at < self.valid_until


@dataclass(frozen=True)
class Scope:
    targets: frozenset[str]
    jurisdiction: str
    consequence_class: str

    def contains(self, other: "Scope") -> bool:
        return (
            other.targets.issubset(self.targets)
            and self.jurisdiction == other.jurisdiction
            and self.consequence_class == other.consequence_class
        )

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class Grant:
    grant_id: str
    principal: str
    capability: str
    scope: Scope
    window: TimeWindow
    register_version: int
    delegator: str
    revoked: bool = False
    self_authored: bool = False

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass
class AuthorityRegister:
    register_id: str
    version: int
    parent_digest: str
    grants: dict[str, Grant]
    trusted_time_observed: bool = True
    current_version: int = 1
    fork_detected: bool = False

    @property
    def content_digest(self) -> str:
        return digest({
            "register_id": self.register_id,
            "version": self.version,
            "parent_digest": self.parent_digest,
            "grants": self.grants,
        })


@dataclass
class Obligation:
    obligation_id: str
    source_uri: str
    content: bytes
    version: int
    scope: Scope
    window: TimeWindow
    superseded: bool = False
    revoked: bool = False
    declared_conflicts: tuple[str, ...] = ()
    actual_conflicts: tuple[str, ...] = ()
    resolved_by: str | None = None

    @property
    def content_digest(self) -> str:
        return digest({"content": self.content})


@dataclass
class Policy:
    policy_id: str
    content: bytes
    version: int
    scope: Scope
    rules: tuple[str, ...]
    design_digest: str
    supersedes: str | None = None
    exception_targets: frozenset[str] = frozenset()

    @property
    def content_digest(self) -> str:
        return digest({"content": self.content, "version": self.version})


@dataclass
class InterpretationBinding:
    source_bytes_digest: str
    canonicaliser_id: str
    canonicaliser_version: str
    canonical_form_digest: str
    parser_id: str
    parser_version: str
    parse_ir_digest: str
    loader_id: str
    loader_version: str
    include_digest: str
    defaults_digest: str
    environment_digest: str
    normalised_executable_digest: str
    engine_instance_id: str
    loaded_closure_digest: str
    runtime_canonicaliser_version: str
    runtime_parser_version: str
    runtime_loader_version: str
    runtime_source_bytes_digest: str
    runtime_include_digest: str
    runtime_defaults_digest: str
    runtime_environment_digest: str
    runtime_normalised_executable_digest: str
    runtime_loaded_closure_digest: str
    runtime_engine_instance_id: str

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass
class ClosureManifest:
    closure_id: str
    root_policy_digest: str
    rule_inventory: tuple[str, ...] | None
    dependencies: dict[str, str]
    engine_id: str
    evaluator_id: str
    config_digest: str
    flags_digest: str
    aggregate_digest: str
    runtime_dependencies: dict[str, str]

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass
class DerivationAttestation:
    attestation_id: str
    version: int
    status: str
    obligation_digest: str
    policy_digest: str
    coverage: dict[str, str]
    assumptions: tuple[str, ...]
    exceptions: tuple[str, ...]
    conflicts: tuple[str, ...]
    principal: str
    grant_id: str
    signature: str = ""
    signed_digest: str = ""

    def signable(self) -> dict[str, Any]:
        return {k: v for k, v in vars(self).items() if k not in {"signature", "signed_digest"}}

    @property
    def content_digest(self) -> str:
        return digest(self.signable())


@dataclass
class ApprovalRecord:
    approval_id: str
    version: int
    status: str
    policy_digest: str
    closure_digest: str
    interpretation_digest: str
    attestation_digest: str
    design_digest: str
    scope_digest: str
    principal: str
    grant_id: str
    approved_at: datetime
    activation_requested_at: datetime
    signature: str = ""
    signed_digest: str = ""

    def signable(self) -> dict[str, Any]:
        return {k: v for k, v in vars(self).items() if k not in {"signature", "signed_digest"}}

    @property
    def content_digest(self) -> str:
        return digest(self.signable())


@dataclass
class ObservationContract:
    contract_id: str
    version: int
    status: str
    issuer: str
    issuer_grant_id: str
    source_id: str
    source_role: str
    endpoint: str
    namespace: str
    object_classes: frozenset[str]
    permitted_predicates: frozenset[str]
    absence_establishes: frozenset[str]
    max_age: timedelta
    temporal_policy_id: str
    interpretation_rule: str
    signature: str = ""
    signed_digest: str = ""

    def signable(self) -> dict[str, Any]:
        value = {k: v for k, v in vars(self).items() if k not in {"signature", "signed_digest"}}
        value["max_age_seconds"] = int(value.pop("max_age").total_seconds())
        return value

    @property
    def content_digest(self) -> str:
        return digest(self.signable())


@dataclass
class ExternalObservation:
    observation_id: str
    contract_id: str
    contract_digest: str
    contract_version: int
    source_id: str
    source_role: str
    endpoint: str
    namespace: str
    queried_object_id: str
    queried_object_class: str
    request_digest: str
    response_digest: str
    observed_at: datetime
    next_update: datetime
    trusted_time_ref: str
    temporal_policy_id: str
    proposition: str
    evidence_state: EvidenceState
    interpretation_rule: str

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class ProofNode:
    object_id: str
    object_type: str
    schema_version: str
    created_at: datetime
    stage: int
    depends_on: tuple[str, ...]
    payload_digest: str

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass
class EngineState:
    engine_instance_id: str
    state_namespace: str
    policy_slot_id: str
    slot_version: int
    active_policy_id: str | None
    active_closure_digest: str | None
    state_version: int
    admitted_policy_ids: set[str] = field(default_factory=set)
    consumed_receipts: set[str] = field(default_factory=set)
    consequence_count: int = 0
    mode: str = "READY"

    @property
    def state_digest(self) -> str:
        return digest({
            "engine_instance_id": self.engine_instance_id,
            "state_namespace": self.state_namespace,
            "policy_slot_id": self.policy_slot_id,
            "slot_version": self.slot_version,
            "active_policy_id": self.active_policy_id,
            "active_closure_digest": self.active_closure_digest,
            "state_version": self.state_version,
            "mode": self.mode,
        })


@dataclass
class Receipt:
    receipt_id: str
    content: dict[str, Any]
    content_digest: str
    signature: str
    signer: str


@dataclass(frozen=True)
class AdmissionSnapshot:
    snapshot_id: str
    checked_at: datetime
    trusted_time_ref: str
    obligation_digest: str
    attestation_id: str
    attestation_digest: str
    approval_id: str
    approval_digest: str
    register_id: str
    register_digest: str
    register_version: int
    observation_contract_digest: str
    observation_digests: tuple[str, ...]
    candidate_digest: str
    closure_digest: str
    interpretation_digest: str
    canonical_scope_digest: str
    target_set_digest: str
    scope_evaluator_version: str
    temporal_policy_id: str
    tcb_digest: str

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class StandingRecord:
    standing_id: str
    policy_id: str
    snapshot_id: str
    snapshot_digest: str
    verdict: AdmissionVerdict
    reasons: tuple[str, ...]
    evaluated_at: datetime
    revalidate_by: datetime
    temporal_policy_id: str
    observation_freshness_basis: tuple[str, ...]

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class OperationAuthorization:
    operation_id: str
    principal: str
    capability: str
    grant_id: str
    grant_digest: str
    register_digest: str
    register_version: int
    scope_digest: str
    target_digest: str
    object_digests: tuple[str, ...]
    context_digest: str

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class DecisionRecord:
    decision_id: str
    policy_admission_id: str
    snapshot_id: str
    snapshot_digest: str
    closure_digest: str
    attestation_digest: str
    standing_digest: str
    validity_limit: datetime
    target_id: str
    target_digest: str
    authority_to_commit: bool

    @property
    def content_digest(self) -> str:
        return digest(self)


@dataclass(frozen=True)
class ActivationRecord:
    transaction_id: str
    policy_slot_id: str
    expected_slot_version: int
    before_state_digest: str
    observed_after_state_digest: str
    operational_result: OperationalResult
    authorization_digest: str
    standing_digest: str

    @property
    def content_digest(self) -> str:
        return digest(self)
