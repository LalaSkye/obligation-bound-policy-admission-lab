from __future__ import annotations

import copy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .canonical import bytes_digest, digest
from .crypto import DemoKeyring
from .model import (
    ActivationRecord,
    AdmissionSnapshot,
    ApprovalRecord,
    AuthorityRegister,
    ClosureManifest,
    DecisionRecord,
    DerivationAttestation,
    EngineState,
    ExternalObservation,
    Grant,
    InterpretationBinding,
    ObservationContract,
    Obligation,
    OperationAuthorization,
    Policy,
    ProofNode,
    Receipt,
    Scope,
    StandingRecord,
    TimeWindow,
)
from .types import (
    AdmissionVerdict,
    EngineMode,
    EvidenceState,
    OperationalResult,
    Outcome,
    PredicateTrace,
)


@dataclass
class Fixture:
    now: datetime
    obligation: Obligation
    claimed_obligation_id: str
    obligation_issuer: str
    obligation_issuer_grant_id: str
    policy: Policy
    register: AuthorityRegister
    closure: ClosureManifest
    interpretation: InterpretationBinding
    derivation: DerivationAttestation | None
    approval: ApprovalRecord
    observation_contract: ObservationContract
    observation: ExternalObservation
    engine: EngineState
    keyring: DemoKeyring
    tcb_digest: str
    actual_tcb_digest: str
    scope_evaluator_version: str
    actual_scope_evaluator_version: str
    target_set_digest: str
    actual_target_set_digest: str
    activation_principal: str
    activation_grant_id: str
    decision_target: str
    incumbent_standing: AdmissionVerdict = AdmissionVerdict.ALLOW
    fallback_standing: AdmissionVerdict | None = None
    checker_enabled: bool = True
    verification_configured: bool = True
    prior_policy_version: int = 0
    latest_policy_version: int = 1
    policy_source_current_digest: str = ""
    use_time: datetime | None = None
    flags: set[str] = field(default_factory=set)
    proof_nodes: list[ProofNode] = field(default_factory=list)
    proof_manifest: dict[str, Any] = field(default_factory=dict)
    receipt: Receipt | None = None
    release_build_ids: tuple[str, str, str] = ("build-a", "build-a", "build-a")

    def clone(self) -> "Fixture":
        return copy.deepcopy(self)


@dataclass
class AdmissionEvaluation:
    outcome: Outcome
    snapshot: AdmissionSnapshot | None = None
    standing: StandingRecord | None = None


def _grant(
    grant_id: str,
    principal: str,
    capability: str,
    scope: Scope,
    window: TimeWindow,
    *,
    self_authored: bool = False,
) -> Grant:
    return Grant(
        grant_id=grant_id,
        principal=principal,
        capability=capability,
        scope=scope,
        window=window,
        register_version=1,
        delegator="root-config",
        self_authored=self_authored,
    )


def _proof_graph(now: datetime, payloads: dict[str, str]) -> tuple[list[ProofNode], dict[str, Any]]:
    rows = [
        ("obligation", "DeclaredObligation", 0, ()),
        ("register", "AuthorityRegisterSnapshot", 0, ()),
        ("candidate", "CandidatePolicy", 0, ()),
        ("closure", "ExecutableClosureManifest", 0, ()),
        ("interpretation", "InterpretationBinding", 0, ()),
        ("tcb", "TrustedComputingBase", 0, ()),
        ("contract", "ObservationContract", 1, ("register", "tcb")),
        ("observation", "ExternalObservation", 2, ("contract",)),
        (
            "precontext",
            "PreAdmissionContext",
            2,
            ("obligation", "register", "candidate", "closure", "interpretation", "tcb", "contract", "observation"),
        ),
        ("derive_auth", "DerivationAuthorization", 3, ("precontext", "register")),
        ("attestation", "DerivationAttestation", 3, ("precontext", "derive_auth")),
        ("approve_auth", "ApprovalAuthorization", 4, ("precontext", "attestation", "register")),
        ("approval", "ApprovalRecord", 4, ("precontext", "attestation", "approve_auth")),
        ("snapshot", "AdmissionSnapshot", 5, ("precontext", "approval")),
        ("standing", "StandingResult", 6, ("snapshot",)),
        ("activate_auth", "ActivationAuthorization", 7, ("snapshot", "standing", "register")),
        ("activation", "ActivationTransaction", 7, ("activate_auth", "standing")),
        ("engine_observation", "EngineObservation", 8, ("activation",)),
        ("decision", "DecisionRecord", 9, ("standing", "engine_observation")),
        ("commit_guard", "FinalCommitGuard", 10, ("decision", "engine_observation")),
        ("commit_result", "CommitBoundaryResult", 10, ("commit_guard",)),
    ]
    nodes = [
        ProofNode(
            object_id=object_id,
            object_type=object_type,
            schema_version="1.0",
            created_at=now + timedelta(microseconds=index),
            stage=stage,
            depends_on=depends_on,
            payload_digest=payloads.get(object_id, digest({"placeholder": object_id})),
        )
        for index, (object_id, object_type, stage, depends_on) in enumerate(rows)
    ]
    ordered = [(node.object_id, node.content_digest, node.stage) for node in nodes]
    manifest = {
        "manifest_id": "manifest-1",
        "validator_version": "0.6",
        "ordered_nodes": ordered,
        "graph_root_digest": digest(ordered),
    }
    return nodes, manifest


def valid_fixture() -> Fixture:
    now = datetime(2026, 8, 26, 12, 0, tzinfo=timezone.utc)
    window = TimeWindow(now - timedelta(days=30), now + timedelta(days=30))
    scope = Scope(frozenset({"device-7"}), "GB", "governed-commit")
    keyring = DemoKeyring()

    grants = {
        "g-register": _grant("g-register", "obligation-issuer", "REGISTER_OBLIGATION", scope, window),
        "g-derive": _grant("g-derive", "deriver", "DERIVE_POLICY", scope, window),
        "g-approve": _grant("g-approve", "approver", "APPROVE_POLICY", scope, window),
        "g-activate": _grant("g-activate", "activator", "ACTIVATE_POLICY", scope, window),
        "g-contract": _grant("g-contract", "contract-issuer", "DECLARE_OBSERVATION_CONTRACT", scope, window),
        "g-revoke": _grant("g-revoke", "revoker", "REVOKE_AUTHORITY", scope, window),
        "g-resolve": _grant("g-resolve", "resolver", "RESOLVE_CONFLICT", scope, window),
    }
    register = AuthorityRegister("register-main", 1, "genesis", grants, current_version=1)
    obligation = Obligation(
        "obl-1",
        "urn:obligation:1",
        b"Operators must block export unless reviewed.",
        1,
        scope,
        window,
    )
    policy = Policy(
        "policy-1",
        b'{"rules":["deny_export","require_review"]}',
        1,
        scope,
        ("deny_export", "require_review"),
        design_digest=digest({"design": "v1"}),
    )
    dependency_map = {"rules.lib": digest({"rules": "v1"}), "data.json": digest({"data": "v1"})}
    closure_aggregate = digest({"policy": policy.content_digest, "dependencies": dependency_map})
    closure = ClosureManifest(
        "closure-1",
        policy.content_digest,
        policy.rules,
        dependency_map,
        "engine-ref",
        "evaluator-ref",
        digest({"config": "v1"}),
        digest({"flags": []}),
        closure_aggregate,
        copy.deepcopy(dependency_map),
    )
    source_digest = bytes_digest(policy.content)
    interpretation = InterpretationBinding(
        source_digest,
        "canon-json",
        "1",
        digest({"canonical": policy.content.decode()}),
        "parser-json",
        "1",
        digest({"ir": list(policy.rules)}),
        "loader-ref",
        "1",
        dependency_map["rules.lib"],
        digest({"defaults": "deny"}),
        digest({"environment": "sealed"}),
        closure_aggregate,
        "engine-1",
        closure_aggregate,
        "1",
        "1",
        "1",
        source_digest,
        dependency_map["rules.lib"],
        digest({"defaults": "deny"}),
        digest({"environment": "sealed"}),
        closure_aggregate,
        closure_aggregate,
        "engine-1",
    )
    derivation = DerivationAttestation(
        "attest-1",
        1,
        "CURRENT",
        obligation.content_digest,
        policy.content_digest,
        {rule: obligation.obligation_id for rule in policy.rules},
        ("declared-inputs-only",),
        (),
        (),
        "deriver",
        "g-derive",
    )
    derivation.signed_digest = derivation.content_digest
    derivation.signature = keyring.sign(derivation.principal, derivation.signed_digest)
    approval = ApprovalRecord(
        "approval-1",
        1,
        "APPROVED",
        policy.content_digest,
        closure.content_digest,
        interpretation.content_digest,
        derivation.content_digest,
        policy.design_digest,
        scope.content_digest,
        "approver",
        "g-approve",
        now - timedelta(minutes=2),
        now - timedelta(minutes=1),
    )
    approval.signed_digest = approval.content_digest
    approval.signature = keyring.sign(approval.principal, approval.signed_digest)
    contract = ObservationContract(
        "obs-contract-1",
        1,
        "CURRENT",
        "contract-issuer",
        "g-contract",
        "revocation-source-A",
        "REVOCATION_STATUS",
        "https://revocation.example.test/v1",
        "authority/main",
        frozenset({"obligation", "grant", "policy"}),
        frozenset({"NOT_REVOKED", "REVOKED"}),
        frozenset({"NOT_REVOKED"}),
        timedelta(minutes=15),
        "utc-strict-v1",
        "signed-record-v1",
    )
    contract.signed_digest = contract.content_digest
    contract.signature = keyring.sign(contract.issuer, contract.signed_digest)
    observation = ExternalObservation(
        "obs-1",
        contract.contract_id,
        contract.content_digest,
        contract.version,
        contract.source_id,
        contract.source_role,
        contract.endpoint,
        contract.namespace,
        obligation.obligation_id,
        "obligation",
        digest({"query": obligation.obligation_id}),
        digest({"status": "not-revoked"}),
        now - timedelta(minutes=1),
        now + timedelta(minutes=14),
        "trusted-clock-1",
        contract.temporal_policy_id,
        "NOT_REVOKED",
        EvidenceState.POSITIVELY_ESTABLISHED,
        contract.interpretation_rule,
    )
    engine = EngineState(
        "engine-1",
        "main",
        "policy-slot-main",
        7,
        "policy-0",
        digest({"incumbent": "closure-0"}),
        12,
        admitted_policy_ids={"policy-0"},
    )
    tcb_digest = digest({"checker": "0.6", "engine": "engine-ref", "adapter": "1"})
    payloads = {
        "obligation": obligation.content_digest,
        "register": register.content_digest,
        "candidate": policy.content_digest,
        "closure": closure.content_digest,
        "interpretation": interpretation.content_digest,
        "tcb": tcb_digest,
        "contract": contract.content_digest,
        "observation": observation.content_digest,
        "attestation": derivation.content_digest,
        "approval": approval.content_digest,
    }
    nodes, manifest = _proof_graph(now, payloads)
    return Fixture(
        now=now,
        obligation=obligation,
        claimed_obligation_id=obligation.obligation_id,
        obligation_issuer="obligation-issuer",
        obligation_issuer_grant_id="g-register",
        policy=policy,
        register=register,
        closure=closure,
        interpretation=interpretation,
        derivation=derivation,
        approval=approval,
        observation_contract=contract,
        observation=observation,
        engine=engine,
        keyring=keyring,
        tcb_digest=tcb_digest,
        actual_tcb_digest=tcb_digest,
        scope_evaluator_version="scope-v1",
        actual_scope_evaluator_version="scope-v1",
        target_set_digest=digest(sorted(scope.targets)),
        actual_target_set_digest=digest(sorted(scope.targets)),
        activation_principal="activator",
        activation_grant_id="g-activate",
        decision_target="device-7",
        policy_source_current_digest=obligation.content_digest,
        use_time=now,
        proof_nodes=nodes,
        proof_manifest=manifest,
    )


class AdmissionHarness:
    def _outcome(
        self,
        verdict: AdmissionVerdict,
        reason: str,
        predicate: str,
        *,
        evidence_state: EvidenceState | None = None,
        operational: OperationalResult = OperationalResult.NOT_ATTEMPTED,
        engine_mode: EngineMode = EngineMode.READY,
        activated: bool = False,
        committed: bool = False,
        consequence_count: int = 0,
        evidence: dict[str, Any] | None = None,
    ) -> Outcome:
        return Outcome(
            admission=verdict,
            operational=operational,
            reason=reason,
            failed_predicate=predicate,
            evidence_state=evidence_state,
            activated=activated,
            committed=committed,
            consequence_count=consequence_count,
            engine_mode=engine_mode,
            traces=[PredicateTrace(predicate, False, reason, evidence_state)],
            evidence=evidence or {},
        )

    def _authorised(self, fixture: Fixture, principal: str, capability: str, grant_id: str, scope: Scope) -> tuple[bool, str]:
        grant = fixture.register.grants.get(grant_id)
        if not grant:
            return False, "AUTHORITY_GRANT_MISSING"
        if grant.principal != principal or grant.capability != capability:
            return False, "AUTHORITY_ROLE_SUBSTITUTION"
        if grant.register_version != fixture.register.version:
            return False, "AUTHORITY_REGISTER_VERSION_MISMATCH"
        if grant.revoked:
            return False, "AUTHORITY_REVOKED"
        if not grant.window.contains(fixture.now):
            return False, "DELEGATION_EXPIRED"
        if not grant.scope.contains(scope):
            return False, "AUTHORITY_SCOPE_MISMATCH"
        if grant.self_authored:
            return False, "SELF_AUTHORISATION"
        return True, "AUTHORITY_ESTABLISHED"

    def validate_graph(self, fixture: Fixture) -> tuple[bool, str]:
        seen: dict[str, ProofNode] = {}
        for node in fixture.proof_nodes:
            if node.object_id in seen:
                return False, "DUPLICATE_PROOF_OBJECT_ID"
            if node.object_id in node.depends_on:
                return False, "INVALID_DEPENDENCY_ORDER"
            seen[node.object_id] = node

        graph = {n.object_id: n.depends_on for n in fixture.proof_nodes}
        if any(dep_id not in graph for deps in graph.values() for dep_id in deps):
            return False, "INVALID_DEPENDENCY_ORDER"

        # Detect a real cycle before checking the serialized topological order.
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(node_id: str) -> bool:
            if node_id in visiting:
                return False
            if node_id in visited:
                return True
            visiting.add(node_id)
            for dep_id in graph.get(node_id, ()):
                if dep_id not in graph or not visit(dep_id):
                    return False
            visiting.remove(node_id)
            visited.add(node_id)
            return True

        if not all(visit(node_id) for node_id in graph):
            return False, "PROOF_GRAPH_CYCLE"

        position = {node.object_id: index for index, node in enumerate(fixture.proof_nodes)}
        for node in fixture.proof_nodes:
            for dep_id in node.depends_on:
                dep = seen[dep_id]
                if position[dep_id] >= position[node.object_id] or dep.stage > node.stage:
                    return False, "INVALID_DEPENDENCY_ORDER"

        ordered = [(n.object_id, n.content_digest, n.stage) for n in fixture.proof_nodes]
        manifest = fixture.proof_manifest
        if manifest.get("ordered_nodes") != ordered or manifest.get("graph_root_digest") != digest(ordered):
            return False, "PROOF_GRAPH_INCOMPLETE"
        required = {"obligation", "register", "contract", "observation", "attestation", "approval", "snapshot", "standing"}
        if not required.issubset(seen):
            return False, "PROOF_GRAPH_INCOMPLETE"
        return True, "PROOF_GRAPH_VALID"

    def _validate_observation(self, fixture: Fixture) -> tuple[AdmissionVerdict, str, str, EvidenceState | None]:
        contract = fixture.observation_contract
        obs = fixture.observation
        ok, reason = self._authorised(fixture, contract.issuer, "DECLARE_OBSERVATION_CONTRACT", contract.issuer_grant_id, fixture.policy.scope)
        if not ok:
            return AdmissionVerdict.DENY, reason, "observation_contract_authority", EvidenceState.POSITIVELY_INVALID
        if contract.status != "CURRENT" or not fixture.keyring.verify(contract.issuer, contract.signed_digest, contract.signature):
            return AdmissionVerdict.DENY, "OBSERVATION_CONTRACT_INVALID", "observation_contract", EvidenceState.POSITIVELY_INVALID
        if obs.contract_id != contract.contract_id or obs.contract_digest != contract.content_digest or obs.contract_version != contract.version:
            return AdmissionVerdict.DENY, "OBSERVATION_CONTRACT_MISMATCH", "observation_contract", EvidenceState.POSITIVELY_INVALID
        if obs.source_id != contract.source_id or obs.endpoint != contract.endpoint:
            return AdmissionVerdict.HOLD, "WRONG_SOURCE", "observation_source", EvidenceState.WRONG_SOURCE
        if obs.namespace != contract.namespace or obs.queried_object_class not in contract.object_classes:
            return AdmissionVerdict.HOLD, "WRONG_NAMESPACE", "observation_namespace", EvidenceState.WRONG_NAMESPACE
        if obs.source_role != contract.source_role or obs.proposition not in contract.permitted_predicates:
            return AdmissionVerdict.DENY, "OBSERVATION_CONTRACT_MISMATCH", "observation_jurisdiction", EvidenceState.POSITIVELY_INVALID
        if obs.temporal_policy_id != contract.temporal_policy_id or obs.interpretation_rule != contract.interpretation_rule:
            return AdmissionVerdict.HOLD, "OBSERVATION_SEMANTICS_UNRESOLVED", "observation_temporal_semantics", EvidenceState.UNKNOWN
        if obs.evidence_state == EvidenceState.SOURCE_UNAVAILABLE:
            return AdmissionVerdict.HOLD, "REVOCATION_SOURCE_UNAVAILABLE", "revocation_current", obs.evidence_state
        if obs.evidence_state == EvidenceState.MALFORMED_RESPONSE:
            return AdmissionVerdict.HOLD, "MALFORMED_OBSERVATION", "revocation_current", obs.evidence_state
        if fixture.now - obs.observed_at > contract.max_age or fixture.now >= obs.next_update or obs.evidence_state == EvidenceState.SOURCE_STALE:
            return AdmissionVerdict.HOLD, "SOURCE_STALE", "revocation_current", EvidenceState.SOURCE_STALE
        if obs.evidence_state == EvidenceState.ABSENCE_OBSERVED and obs.proposition not in contract.absence_establishes:
            return AdmissionVerdict.HOLD, "NEGATIVE_EVIDENCE_UNWARRANTED", "revocation_current", EvidenceState.ABSENCE_OBSERVED
        if obs.evidence_state == EvidenceState.CONFLICT:
            return AdmissionVerdict.HOLD, "OBSERVATION_CONFLICT", "revocation_current", EvidenceState.CONFLICT
        if obs.evidence_state == EvidenceState.POSITIVELY_INVALID:
            return AdmissionVerdict.DENY, "SOURCE_OBLIGATION_SUPERSEDED", "revocation_current", obs.evidence_state
        if obs.evidence_state != EvidenceState.POSITIVELY_ESTABLISHED:
            return AdmissionVerdict.HOLD, "OBSERVATION_UNKNOWN", "revocation_current", obs.evidence_state
        return AdmissionVerdict.ALLOW, "OBSERVATION_ESTABLISHED", "revocation_current", obs.evidence_state

    def _validate_interpretation(self, fixture: Fixture) -> tuple[AdmissionVerdict, str, str]:
        i = fixture.interpretation
        if i.source_bytes_digest != bytes_digest(fixture.policy.content):
            return AdmissionVerdict.DENY, "SOURCE_BYTES_MISMATCH", "interpretation_identity"
        if (
            i.canonicaliser_version != i.runtime_canonicaliser_version
            or i.parser_version != i.runtime_parser_version
            or i.loader_version != i.runtime_loader_version
        ):
            return AdmissionVerdict.DENY, "INTERPRETATION_VERSION_MISMATCH", "interpretation_identity"
        if i.runtime_source_bytes_digest != i.source_bytes_digest:
            return AdmissionVerdict.DENY, "LOADED_SOURCE_MISMATCH", "interpretation_identity"
        if (
            i.include_digest != i.runtime_include_digest
            or i.defaults_digest != i.runtime_defaults_digest
            or i.environment_digest != i.runtime_environment_digest
        ):
            return AdmissionVerdict.DENY, "LOADED_CLOSURE_MISMATCH", "interpretation_identity"
        if i.normalised_executable_digest != i.runtime_normalised_executable_digest:
            return AdmissionVerdict.DENY, "EXECUTED_FORM_MISMATCH", "interpretation_identity"
        if i.engine_instance_id != i.runtime_engine_instance_id or i.loaded_closure_digest != i.runtime_loaded_closure_digest:
            return AdmissionVerdict.DENY, "ENGINE_INTERPRETATION_MISMATCH", "interpretation_identity"
        return AdmissionVerdict.ALLOW, "INTERPRETATION_BOUND", "interpretation_identity"

    def admit(self, fixture: Fixture) -> AdmissionEvaluation:
        if not fixture.checker_enabled or not fixture.verification_configured:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "CHECKER_DISABLED", "verification_configuration", engine_mode=EngineMode.HALTED))
        if fixture.claimed_obligation_id != fixture.obligation.obligation_id:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "OBLIGATION_ID_MISMATCH", "obligation_identity"))
        if fixture.policy_source_current_digest != fixture.obligation.content_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "OBLIGATION_CONTENT_DIGEST_MISMATCH", "obligation_identity"))
        if fixture.obligation.superseded or fixture.obligation.revoked:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "SOURCE_OBLIGATION_SUPERSEDED", "obligation_current", evidence_state=EvidenceState.POSITIVELY_INVALID))
        if not fixture.obligation.window.contains(fixture.now):
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "OBLIGATION_EXPIRED", "obligation_current"))
        if not fixture.obligation.scope.contains(fixture.policy.scope):
            reason = "JURISDICTION_NOT_COVERED_BY_OBLIGATION" if fixture.obligation.scope.jurisdiction != fixture.policy.scope.jurisdiction else "DERIVED_SCOPE_EXCEEDS_SOURCE"
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, reason, "obligation_scope"))
        if fixture.register.version < fixture.register.current_version:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "AUTHORITY_REGISTER_ROLLBACK", "authority_register_lineage"))
        if fixture.register.fork_detected:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "AUTHORITY_REGISTER_FORK", "authority_register_lineage"))
        if not fixture.register.trusted_time_observed:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "TRUSTED_TIME_ABSENT", "currentness"))
        ok, reason = self._authorised(fixture, fixture.obligation_issuer, "REGISTER_OBLIGATION", fixture.obligation_issuer_grant_id, fixture.obligation.scope)
        if not ok:
            mapped = "ISSUER_NOT_AUTHORISED" if reason in {"AUTHORITY_GRANT_MISSING", "AUTHORITY_ROLE_SUBSTITUTION"} else reason
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, mapped, "obligation_issuer_authority"))
        if fixture.obligation.actual_conflicts and set(fixture.obligation.actual_conflicts) - set(fixture.obligation.declared_conflicts):
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "UNRESOLVED_CONFLICT_UNDECLARED", "conflict_resolution"))
        if fixture.obligation.resolved_by:
            ok, reason = self._authorised(fixture, fixture.obligation.resolved_by, "RESOLVE_CONFLICT", "g-resolve", fixture.obligation.scope)
            if not ok:
                return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, reason, "conflict_resolution"))
        if fixture.policy.version < fixture.latest_policy_version:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "SUPERSEDED_VERSION_REPLAY", "policy_version"))
        if "exception_generalised" in fixture.flags:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "EXCEPTION_GENERALISED", "policy_exception_scope"))
        if fixture.derivation is None:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "DERIVATION_ABSENT_OR_UNVERIFIABLE", "derivation_attestation"))
        d = fixture.derivation
        if d.status != "CURRENT":
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "DERIVATION_STATUS_UNRESOLVED", "derivation_attestation"))
        if d.obligation_digest != fixture.obligation.content_digest or d.policy_digest != fixture.policy.content_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "DERIVATION_DIGEST_MISMATCH", "derivation_attestation"))
        if d.signed_digest != d.content_digest or not fixture.keyring.verify(d.principal, d.signed_digest, d.signature):
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "DERIVATION_SIGNATURE_INVALID", "derivation_attestation"))
        ok, reason = self._authorised(fixture, d.principal, "DERIVE_POLICY", d.grant_id, fixture.policy.scope)
        if not ok:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, reason, "derive_operation_authority"))
        if fixture.closure.rule_inventory is None:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "RULE_SET_UNRESOLVED", "total_rule_coverage"))
        unmapped = set(fixture.closure.rule_inventory) - set(d.coverage)
        if unmapped:
            reason = "DERIVATION_UNSUPPORTED" if not d.coverage else "UNMAPPED_EXECUTABLE_RULE"
            verdict = AdmissionVerdict.HOLD if not d.coverage else AdmissionVerdict.DENY
            return AdmissionEvaluation(self._outcome(verdict, reason, "total_rule_coverage"))
        a = fixture.approval
        if a.approved_at > a.activation_requested_at:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "APPROVAL_AFTER_USE", "approval_temporal_order"))
        if (
            a.policy_digest != fixture.policy.content_digest
            or a.closure_digest != fixture.closure.content_digest
            or a.interpretation_digest != fixture.interpretation.content_digest
            or a.attestation_digest != d.content_digest
            or a.scope_digest != fixture.policy.scope.content_digest
        ):
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "APPROVAL_NOT_BOUND_TO_ARTEFACT", "approval_binding"))
        if a.design_digest != fixture.policy.design_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "APPROVAL_INHERITED_ACROSS_CHANGE", "approval_binding"))
        if a.signed_digest != a.content_digest or not fixture.keyring.verify(a.principal, a.signed_digest, a.signature):
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "APPROVAL_SIGNATURE_INVALID", "approval_binding"))
        ok, reason = self._authorised(fixture, a.principal, "APPROVE_POLICY", a.grant_id, fixture.policy.scope)
        if not ok:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, reason, "approve_operation_authority"))
        if fixture.closure.root_policy_digest != fixture.policy.content_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "CLOSURE_ROOT_MISMATCH", "executable_closure"))
        if fixture.closure.dependencies != fixture.closure.runtime_dependencies:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "CLOSURE_MISMATCH", "executable_closure"))
        verdict, reason, predicate = self._validate_interpretation(fixture)
        if verdict != AdmissionVerdict.ALLOW:
            return AdmissionEvaluation(self._outcome(verdict, reason, predicate))
        if fixture.scope_evaluator_version != fixture.actual_scope_evaluator_version:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "SCOPE_EVALUATOR_MISMATCH", "canonical_scope"))
        if fixture.target_set_digest != fixture.actual_target_set_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.DENY, "TARGET_SET_MISMATCH", "canonical_scope"))
        if fixture.actual_tcb_digest != fixture.tcb_digest:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "TCB_VERSION_MISMATCH", "trusted_computing_base"))
        if "snapshot_race" in fixture.flags:
            return AdmissionEvaluation(self._outcome(AdmissionVerdict.HOLD, "SNAPSHOT_COHERENCE_FAILED", "atomic_snapshot"))
        obs_verdict, obs_reason, obs_predicate, evidence_state = self._validate_observation(fixture)
        if obs_verdict != AdmissionVerdict.ALLOW:
            return AdmissionEvaluation(self._outcome(obs_verdict, obs_reason, obs_predicate, evidence_state=evidence_state))
        graph_ok, graph_reason = self.validate_graph(fixture)
        if not graph_ok:
            verdict = AdmissionVerdict.DENY
            predicate = "proof_graph"
            return AdmissionEvaluation(self._outcome(verdict, graph_reason, predicate, engine_mode=EngineMode.HALTED))

        snapshot = AdmissionSnapshot(
            "snapshot-1",
            fixture.now,
            fixture.observation.trusted_time_ref,
            fixture.obligation.content_digest,
            d.attestation_id,
            d.content_digest,
            a.approval_id,
            a.content_digest,
            fixture.register.register_id,
            fixture.register.content_digest,
            fixture.register.version,
            fixture.observation_contract.content_digest,
            (fixture.observation.content_digest,),
            fixture.policy.content_digest,
            fixture.closure.content_digest,
            fixture.interpretation.content_digest,
            fixture.policy.scope.content_digest,
            fixture.target_set_digest,
            fixture.scope_evaluator_version,
            fixture.observation_contract.temporal_policy_id,
            fixture.tcb_digest,
        )
        revalidate_by = min(
            fixture.observation.next_update,
            fixture.observation.observed_at + fixture.observation_contract.max_age,
            fixture.obligation.window.valid_until,
        )
        standing = StandingRecord(
            "standing-1",
            fixture.policy.policy_id,
            snapshot.snapshot_id,
            snapshot.content_digest,
            AdmissionVerdict.ALLOW,
            (),
            fixture.now,
            revalidate_by,
            fixture.observation_contract.temporal_policy_id,
            (fixture.observation.content_digest,),
        )
        outcome = Outcome(
            admission=AdmissionVerdict.ALLOW,
            reason="ALL_REQUIRED_PREDICATES_ESTABLISHED",
            failed_predicate="",
            evidence_state=EvidenceState.POSITIVELY_ESTABLISHED,
            engine_mode=EngineMode.READY,
            traces=[PredicateTrace("standing", True, "ALL_REQUIRED_PREDICATES_ESTABLISHED", EvidenceState.POSITIVELY_ESTABLISHED)],
            evidence={"snapshot_digest": snapshot.content_digest, "standing_digest": standing.content_digest},
        )
        return AdmissionEvaluation(outcome, snapshot, standing)

    def _operation_authorization(self, fixture: Fixture, capability: str, principal: str, grant_id: str, context_digest: str) -> tuple[OperationAuthorization | None, str]:
        ok, reason = self._authorised(fixture, principal, capability, grant_id, fixture.policy.scope)
        if not ok:
            return None, reason
        grant = fixture.register.grants[grant_id]
        return OperationAuthorization(
            f"op-{capability.lower()}",
            principal,
            capability,
            grant_id,
            grant.content_digest,
            fixture.register.content_digest,
            fixture.register.version,
            fixture.policy.scope.content_digest,
            fixture.target_set_digest,
            (fixture.policy.content_digest, fixture.closure.content_digest),
            context_digest,
        ), "AUTHORITY_ESTABLISHED"

    def activate(self, fixture: Fixture, evaluation: AdmissionEvaluation) -> tuple[Outcome, ActivationRecord | None]:
        if evaluation.outcome.admission != AdmissionVerdict.ALLOW or not evaluation.standing or not evaluation.snapshot:
            if "partial_activation" in fixture.flags:
                fixture.engine.active_policy_id = fixture.policy.policy_id
                fixture.engine.slot_version += 1
                fixture.engine.mode = "HALTED"
                return self._outcome(
                    evaluation.outcome.admission,
                    "RECEIPT_STATE_DISAGREEMENT",
                    "activation_integrity",
                    operational=OperationalResult.INTEGRITY_FAILURE,
                    engine_mode=EngineMode.HALTED,
                ), None
            return evaluation.outcome, None
        auth, reason = self._operation_authorization(
            fixture,
            "ACTIVATE_POLICY",
            fixture.activation_principal,
            fixture.activation_grant_id,
            evaluation.snapshot.content_digest,
        )
        if not auth:
            return self._outcome(AdmissionVerdict.DENY, reason, "activate_operation_authority"), None
        interpretation_verdict, interpretation_reason, _ = self._validate_interpretation(fixture)
        if interpretation_verdict != AdmissionVerdict.ALLOW:
            fixture.engine.mode = "HALTED"
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "CHECKED_EXECUTED_INTERPRETATION_MISMATCH",
                "activation_interpretation_integrity",
                operational=OperationalResult.INTEGRITY_FAILURE,
                engine_mode=EngineMode.HALTED,
                evidence={"underlying_reason": interpretation_reason},
            ), None
        before = fixture.engine.state_digest
        expected_slot_version = fixture.engine.slot_version
        if "transaction_conflict" in fixture.flags:
            fixture.engine.slot_version += 1
        if fixture.engine.slot_version != expected_slot_version:
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "TRANSACTION_CONFLICT",
                "activation_compare_and_swap",
                operational=OperationalResult.TRANSACTION_CONFLICT,
            ), None
        if "transaction_failure" in fixture.flags:
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "TRANSACTION_FAILURE",
                "activation_transaction",
                operational=OperationalResult.TRANSACTION_FAILURE,
                engine_mode=EngineMode.HALTED,
            ), None
        fixture.engine.active_policy_id = fixture.policy.policy_id
        fixture.engine.active_closure_digest = fixture.closure.aggregate_digest
        fixture.engine.slot_version += 1
        fixture.engine.state_version += 1
        fixture.engine.admitted_policy_ids.add(fixture.policy.policy_id)
        fixture.engine.mode = "ACTIVE"
        if "state_indeterminate" in fixture.flags:
            fixture.engine.active_closure_digest = None
            fixture.engine.mode = "QUARANTINED"
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "STATE_INDETERMINATE",
                "engine_state_observation",
                operational=OperationalResult.STATE_INDETERMINATE,
                engine_mode=EngineMode.QUARANTINED,
            ), None
        if "readback_mismatch" in fixture.flags:
            fixture.engine.active_closure_digest = digest({"unexpected": "closure"})
            fixture.engine.mode = "HALTED"
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "ACTIVATION_READBACK_MISMATCH",
                "activation_integrity",
                operational=OperationalResult.INTEGRITY_FAILURE,
                engine_mode=EngineMode.HALTED,
            ), None
        after = fixture.engine.state_digest
        record = ActivationRecord(
            "tx-1",
            fixture.engine.policy_slot_id,
            expected_slot_version,
            before,
            after,
            OperationalResult.COMMITTED,
            auth.content_digest,
            evaluation.standing.content_digest,
        )
        return Outcome(
            admission=AdmissionVerdict.ALLOW,
            operational=OperationalResult.COMMITTED,
            reason="ACTIVATION_COMMITTED",
            activated=True,
            committed=False,
            engine_mode=EngineMode.ACTIVE,
            evidence={"activation_digest": record.content_digest, "observed_state_digest": after},
        ), record

    def issue_decision(self, fixture: Fixture, evaluation: AdmissionEvaluation, *, authoritative: bool = True) -> tuple[Outcome, DecisionRecord | None]:
        if (
            fixture.engine.active_policy_id is not None
            and fixture.engine.active_policy_id not in fixture.engine.admitted_policy_ids
        ):
            fixture.engine.mode = "HALTED"
            return self._outcome(
                AdmissionVerdict.DENY,
                "UNADMITTED_ACTIVE_POLICY",
                "declared_activation_surface",
                operational=OperationalResult.HALTED,
                engine_mode=EngineMode.HALTED,
            ), None
        if fixture.decision_target not in fixture.policy.scope.targets:
            return self._outcome(
                AdmissionVerdict.DENY,
                "TARGET_OUT_OF_SCOPE",
                "decision_target",
                activated=fixture.engine.active_policy_id == fixture.policy.policy_id,
                engine_mode=EngineMode.ACTIVE if fixture.engine.active_policy_id == fixture.policy.policy_id else EngineMode.READY,
            ), None
        if fixture.policy.policy_id not in fixture.engine.admitted_policy_ids:
            return self._outcome(AdmissionVerdict.DENY, "DECISION_POLICY_NOT_ADMITTED", "policy_admission"), None
        if not evaluation.standing or not evaluation.snapshot:
            return self._outcome(AdmissionVerdict.HOLD, "CURRENT_STANDING_UNESTABLISHED", "standing"), None
        use_time = fixture.use_time or fixture.now
        if use_time >= evaluation.standing.revalidate_by:
            return self._outcome(
                AdmissionVerdict.HOLD,
                "STANDING_EXPIRED",
                "standing_current",
                activated=fixture.engine.active_policy_id == fixture.policy.policy_id,
                engine_mode=EngineMode.ACTIVE if fixture.engine.active_policy_id == fixture.policy.policy_id else EngineMode.READY,
            ), None
        decision = DecisionRecord(
            "decision-1",
            fixture.policy.policy_id,
            evaluation.snapshot.snapshot_id,
            evaluation.snapshot.content_digest,
            fixture.closure.content_digest,
            fixture.derivation.content_digest if fixture.derivation else "",
            evaluation.standing.content_digest,
            evaluation.standing.revalidate_by,
            fixture.decision_target,
            digest({"target": fixture.decision_target}),
            authoritative,
        )
        return Outcome(
            admission=AdmissionVerdict.ALLOW,
            reason="DECISION_RECORD_ISSUED",
            activated=fixture.engine.active_policy_id == fixture.policy.policy_id,
            engine_mode=EngineMode.ACTIVE,
            evidence={"decision_digest": decision.content_digest},
        ), decision

    def commit(
        self,
        fixture: Fixture,
        evaluation: AdmissionEvaluation,
        activation: ActivationRecord | None,
        decision: DecisionRecord | None,
    ) -> Outcome:
        if "hidden_commit_route" in fixture.flags:
            return self._outcome(
                AdmissionVerdict.DENY,
                "UNMODELLED_CONSEQUENCE_ROUTE",
                "bounded_non_bypassability",
                operational=OperationalResult.HALTED,
                engine_mode=EngineMode.HALTED,
                activated=fixture.engine.active_policy_id == fixture.policy.policy_id,
            )
        if decision is None:
            return self._outcome(AdmissionVerdict.HOLD, "DECISION_RECORD_MISSING", "commit_authority")
        if not decision.authority_to_commit or "diagnostic_authority" in fixture.flags:
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "NO_AUTHORITY_TO_COMMIT",
                "commit_authority",
                operational=OperationalResult.NOT_ATTEMPTED,
                activated=True,
                engine_mode=EngineMode.ACTIVE,
            )
        if not evaluation.standing or not evaluation.snapshot:
            return self._outcome(AdmissionVerdict.HOLD, "CURRENT_STANDING_UNESTABLISHED", "standing_current")
        use_time = fixture.use_time or fixture.now
        if use_time >= evaluation.standing.revalidate_by or use_time >= decision.validity_limit:
            return self._outcome(
                AdmissionVerdict.HOLD,
                "STANDING_EXPIRED",
                "standing_current",
                activated=True,
                engine_mode=EngineMode.ACTIVE,
            )
        if fixture.engine.mode == "QUARANTINED":
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "STATE_INDETERMINATE",
                "engine_state_observation",
                operational=OperationalResult.STATE_INDETERMINATE,
                engine_mode=EngineMode.QUARANTINED,
            )
        if fixture.engine.mode == "HALTED":
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "ENGINE_HALTED",
                "operational_integrity",
                operational=OperationalResult.HALTED,
                engine_mode=EngineMode.HALTED,
            )
        expected = {
            "engine_instance_id": fixture.engine.engine_instance_id,
            "state_namespace": fixture.engine.state_namespace,
            "slot_version": fixture.engine.slot_version,
            "state_version": fixture.engine.state_version,
            "closure": fixture.engine.active_closure_digest,
            "target": fixture.actual_target_set_digest,
            "snapshot": evaluation.snapshot.content_digest,
            "standing": evaluation.standing.content_digest,
        }
        if "adapter_mismatch" in fixture.flags:
            observed = dict(expected, engine_instance_id="engine-other")
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "ADAPTER_INSTANCE_MISMATCH",
                "commit_adapter_consistency",
                operational=OperationalResult.INTEGRITY_FAILURE,
                activated=True,
                engine_mode=EngineMode.HALTED,
            )
        if "mutate_after_guard" in fixture.flags:
            fixture.engine.state_version += 1
        observed = {
            "engine_instance_id": fixture.engine.engine_instance_id,
            "state_namespace": fixture.engine.state_namespace,
            "slot_version": fixture.engine.slot_version,
            "state_version": fixture.engine.state_version,
            "closure": fixture.engine.active_closure_digest,
            "target": fixture.actual_target_set_digest,
            "snapshot": evaluation.snapshot.content_digest,
            "standing": evaluation.standing.content_digest,
        }
        if expected != observed:
            return self._outcome(
                AdmissionVerdict.ALLOW,
                "COMMIT_PRECONDITION_CONFLICT",
                "final_commit_guard",
                operational=OperationalResult.COMMIT_PRECONDITION_CONFLICT,
                activated=True,
                engine_mode=EngineMode.ACTIVE,
                evidence={"expected_state": digest(expected), "observed_state": digest(observed)},
            )
        fixture.engine.consequence_count += 1
        fixture.engine.state_version += 1
        return Outcome(
            admission=AdmissionVerdict.ALLOW,
            operational=OperationalResult.COMMITTED,
            reason="GOVERNED_CONSEQUENCE_COMMITTED",
            activated=True,
            committed=True,
            consequence_count=1,
            engine_mode=EngineMode.ACTIVE,
            evidence={"guarded_state_digest": digest(expected), "consequence_count": 1},
        )

    def make_receipt(self, fixture: Fixture, content: dict[str, Any], signer: str = "receipt-signer") -> Receipt:
        content_digest = digest(content)
        return Receipt("receipt-1", content, content_digest, fixture.keyring.sign(signer, content_digest), signer)

    def validate_receipt(self, fixture: Fixture, receipt: Receipt) -> bool:
        return receipt.content_digest == digest(receipt.content) and fixture.keyring.verify(receipt.signer, receipt.content_digest, receipt.signature)

    def resolve_after_candidate_failure(self, fixture: Fixture, candidate: AdmissionEvaluation) -> Outcome:
        if candidate.outcome.admission == AdmissionVerdict.ALLOW:
            return candidate.outcome
        if fixture.incumbent_standing == AdmissionVerdict.DENY:
            return self._outcome(AdmissionVerdict.DENY, "INCUMBENT_REVOKED", "incumbent_current_standing")
        if fixture.incumbent_standing == AdmissionVerdict.HOLD and fixture.fallback_standing is None:
            return self._outcome(AdmissionVerdict.HOLD, "INCUMBENT_STANDING_UNKNOWN", "incumbent_current_standing")
        if fixture.fallback_standing == AdmissionVerdict.ALLOW:
            return Outcome(AdmissionVerdict.ALLOW, reason="FALLBACK_INDEPENDENTLY_ESTABLISHED")
        if fixture.fallback_standing in {AdmissionVerdict.HOLD, AdmissionVerdict.DENY}:
            return self._outcome(AdmissionVerdict.HOLD, "NO_POLICY_STANDING", "fallback_current_standing")
        return candidate.outcome
