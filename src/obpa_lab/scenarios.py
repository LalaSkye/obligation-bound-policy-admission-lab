from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

from .canonical import digest
from .harness import AdmissionEvaluation, AdmissionHarness, valid_fixture
from .model import StandingRecord
from .types import AdmissionVerdict, EngineMode, EvidenceState, OperationalResult, Outcome


def _resign_derivation(f) -> None:
    assert f.derivation is not None
    f.derivation.signed_digest = f.derivation.content_digest
    f.derivation.signature = f.keyring.sign(f.derivation.principal, f.derivation.signed_digest)


def _resign_approval(f) -> None:
    f.approval.signed_digest = f.approval.content_digest
    f.approval.signature = f.keyring.sign(f.approval.principal, f.approval.signed_digest)


def _rebind_approval(f) -> None:
    assert f.derivation is not None
    f.approval.policy_digest = f.policy.content_digest
    f.approval.closure_digest = f.closure.content_digest
    f.approval.interpretation_digest = f.interpretation.content_digest
    f.approval.attestation_digest = f.derivation.content_digest
    f.approval.design_digest = f.policy.design_digest
    f.approval.scope_digest = f.policy.scope.content_digest
    _resign_approval(f)


def _resign_contract(f) -> None:
    f.observation_contract.signed_digest = f.observation_contract.content_digest
    f.observation_contract.signature = f.keyring.sign(
        f.observation_contract.issuer,
        f.observation_contract.signed_digest,
    )
    f.observation.contract_digest = f.observation_contract.content_digest
    f.observation.contract_version = f.observation_contract.version


def _candidate_failure(f, h: AdmissionHarness) -> AdmissionEvaluation:
    f.claimed_obligation_id = "wrong-obligation"
    return h.admit(f)


def _activated_flow(f, h: AdmissionHarness):
    evaluation = h.admit(f)
    activation_outcome, activation = h.activate(f, evaluation)
    return evaluation, activation_outcome, activation


def run_attack(attack_id: int) -> Outcome:
    h = AdmissionHarness()
    f = valid_fixture()

    if attack_id == 1:
        f.policy.scope = replace(f.policy.scope, targets=frozenset({"device-99"}))
        return h.admit(f).outcome
    if attack_id == 2:
        del f.register.grants[f.obligation_issuer_grant_id]
        return h.admit(f).outcome
    if attack_id == 3:
        grant = f.register.grants[f.obligation_issuer_grant_id]
        f.register.grants[f.obligation_issuer_grant_id] = replace(
            grant,
            window=replace(grant.window, valid_until=f.now - timedelta(seconds=1)),
        )
        return h.admit(f).outcome
    if attack_id == 4:
        f.policy.scope = replace(f.policy.scope, targets=frozenset({"device-7", "device-8"}))
        return h.admit(f).outcome
    if attack_id == 5:
        f.policy.scope = replace(f.policy.scope, jurisdiction="US")
        return h.admit(f).outcome
    if attack_id == 6:
        f.observation.evidence_state = EvidenceState.POSITIVELY_INVALID
        outcome = h.admit(f).outcome
        outcome.sequence = ["HOLD:SOURCE_STATUS_PENDING", "DENY:SOURCE_OBLIGATION_SUPERSEDED"]
        return outcome
    if attack_id == 7:
        f.policy.version = 0
        f.latest_policy_version = 1
        return h.admit(f).outcome
    if attack_id == 8:
        f.derivation = None
        return h.admit(f).outcome
    if attack_id == 9:
        f.approval.approved_at = f.now
        f.approval.activation_requested_at = f.now - timedelta(minutes=1)
        _resign_approval(f)
        return h.admit(f).outcome
    if attack_id == 10:
        f.approval.policy_digest = digest({"other": "policy"})
        _resign_approval(f)
        return h.admit(f).outcome
    if attack_id == 11:
        evaluation, _, _ = _activated_flow(f, h)
        f.decision_target = "device-99"
        return h.issue_decision(f, evaluation)[0]
    if attack_id == 12:
        grant = f.register.grants[f.obligation_issuer_grant_id]
        f.register.grants[f.obligation_issuer_grant_id] = replace(grant, self_authored=True)
        return h.admit(f).outcome
    if attack_id == 13:
        assert f.derivation is not None
        f.derivation.coverage = {}
        _resign_derivation(f)
        return h.admit(f).outcome
    if attack_id == 14:
        f.obligation.actual_conflicts = ("conflict-1",)
        return h.admit(f).outcome
    if attack_id == 15:
        f.flags.add("exception_generalised")
        return h.admit(f).outcome
    if attack_id == 16:
        f.policy.design_digest = digest({"design": "v2"})
        return h.admit(f).outcome
    if attack_id == 17:
        evaluation = h.admit(f)
        # Test hook claims ALLOW, but the engine has no admission-set entry.
        return h.issue_decision(f, evaluation)[0]
    if attack_id == 18:
        evaluation = h.admit(f)
        outcome, _ = h.issue_decision(f, evaluation)
        outcome.reason = "ENFORCEMENT_ADMISSION_TOKEN_MISSING"
        outcome.failed_predicate = "enforcement_admission_token"
        return outcome
    if attack_id == 19:
        f.engine.active_policy_id = f.policy.policy_id
        f.engine.active_closure_digest = f.closure.aggregate_digest
        f.engine.mode = "HALTED"
        return h._outcome(
            AdmissionVerdict.DENY,
            "UNADMITTED_ACTIVE_POLICY",
            "declared_activation_surface",
            operational=OperationalResult.HALTED,
            engine_mode=EngineMode.HALTED,
        )
    if attack_id == 20:
        receipt = h.make_receipt(f, {"policy": f.policy.policy_id, "valid_until": f.now.isoformat()})
        f.engine.consumed_receipts.add(receipt.receipt_id)
        return h._outcome(AdmissionVerdict.DENY, "RECEIPT_REPLAY", "receipt_currentness")
    if attack_id == 21:
        candidate = _candidate_failure(f, h)
        f.incumbent_standing = AdmissionVerdict.DENY
        return h.resolve_after_candidate_failure(f, candidate)
    if attack_id == 22:
        candidate = _candidate_failure(f, h)
        f.incumbent_standing = AdmissionVerdict.HOLD
        return h.resolve_after_candidate_failure(f, candidate)
    if attack_id == 23:
        evaluation, _, _ = _activated_flow(f, h)
        f.use_time = evaluation.standing.revalidate_by + timedelta(microseconds=1)
        return h.issue_decision(f, evaluation)[0]
    if attack_id == 24:
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation)
        f.use_time = evaluation.standing.revalidate_by + timedelta(microseconds=1)
        return h.commit(f, evaluation, activation, decision)
    if attack_id == 25:
        f.flags.add("snapshot_race")
        return h.admit(f).outcome
    if attack_id == 26:
        f.closure.runtime_dependencies["rules.lib"] = digest({"rules": "v2"})
        _rebind_approval(f)
        return h.admit(f).outcome
    if attack_id == 27:
        f.flags.add("partial_activation")
        evaluation = _candidate_failure(f, h)
        return h.activate(f, evaluation)[0]
    if attack_id == 28:
        assert f.derivation is not None
        f.derivation.principal = "activator"
        _resign_derivation(f)
        return h.admit(f).outcome
    if attack_id == 29:
        f.register.current_version = 2
        return h.admit(f).outcome
    if attack_id == 30:
        f.policy_source_current_digest = digest({"changed": "bytes"})
        return h.admit(f).outcome
    if attack_id == 31:
        f.observation.evidence_state = EvidenceState.SOURCE_UNAVAILABLE
        return h.admit(f).outcome
    if attack_id == 32:
        f.flags.add("hidden_commit_route")
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation)
        return h.commit(f, evaluation, activation, decision)
    if attack_id == 33:
        candidate = _candidate_failure(f, h)
        f.incumbent_standing = AdmissionVerdict.HOLD
        f.fallback_standing = AdmissionVerdict.HOLD
        outcome = h.resolve_after_candidate_failure(f, candidate)
        outcome.reason = "NO_POLICY_STANDING"
        outcome.failed_predicate = "fallback_current_standing"
        return outcome
    if attack_id == 34:
        f.actual_tcb_digest = digest({"checker": "modified"})
        return h.admit(f).outcome
    if attack_id == 35:
        assert f.derivation is not None
        f.derivation.assumptions = ("mutated-after-snapshot",)
        return h.admit(f).outcome
    if attack_id == 36:
        evaluation = h.admit(f)
        f.activation_principal = "rogue-actor"
        return h.activate(f, evaluation)[0]
    if attack_id == 37:
        evaluation = h.admit(f)
        f.flags.add("readback_mismatch")
        return h.activate(f, evaluation)[0]
    if attack_id == 38:
        f.closure.rule_inventory = (*f.policy.rules, "unmapped_rule")
        return h.admit(f).outcome
    if attack_id == 39:
        f.closure.rule_inventory = None
        return h.admit(f).outcome
    if attack_id == 40:
        f.actual_scope_evaluator_version = "scope-v2"
        return h.admit(f).outcome
    if attack_id == 41:
        f.observation.source_id = "revocation-source-B"
        return h.admit(f).outcome
    if attack_id == 42:
        f.observation.source_role = "MIRROR_ONLY"
        return h.admit(f).outcome
    if attack_id == 43:
        f.observation.evidence_state = EvidenceState.ABSENCE_OBSERVED
        f.observation_contract.absence_establishes = frozenset()
        _resign_contract(f)
        return h.admit(f).outcome
    if attack_id == 44:
        f.interpretation.runtime_parser_version = "2"
        _rebind_approval(f)
        return h.admit(f).outcome
    if attack_id == 45:
        f.interpretation.runtime_include_digest = digest({"includes": "changed"})
        _rebind_approval(f)
        return h.admit(f).outcome
    if attack_id == 46:
        evaluation = h.admit(f)
        f.interpretation.runtime_normalised_executable_digest = digest({"executed": "B"})
        return h.activate(f, evaluation)[0]
    if attack_id == 47:
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation)
        f.use_time = evaluation.standing.revalidate_by + timedelta(seconds=1)
        return h.commit(f, evaluation, activation, decision)
    if attack_id == 48:
        evaluation = h.admit(f)
        f.flags.add("state_indeterminate")
        return h.activate(f, evaluation)[0]
    if attack_id == 49:
        evaluation = h.admit(f)
        winner, _ = h.activate(f, evaluation)
        f.flags.add("transaction_conflict")
        loser, _ = h.activate(f, evaluation)
        loser.activated = winner.activated
        loser.engine_mode = EngineMode.ACTIVE
        loser.operation_results = [OperationalResult.COMMITTED, OperationalResult.TRANSACTION_CONFLICT]
        loser.evidence["winner_count"] = 1
        return loser
    if attack_id == 50:
        # Deliberately wrong implementation outcome. The typed oracle must reject it.
        return h._outcome(AdmissionVerdict.HOLD, "CONFIGURATION_MISSING", "configuration")
    if attack_id == 51:
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation, authoritative=False)
        f.flags.add("diagnostic_authority")
        return h.commit(f, evaluation, activation, decision)
    if attack_id == 52:
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation)
        f.flags.add("adapter_mismatch")
        return h.commit(f, evaluation, activation, decision)
    if attack_id == 53:
        receipt = h.make_receipt(f, {"decision": "DENY", "before": f.engine.state_digest})
        receipt.content["decision"] = "ALLOW"
        valid = h.validate_receipt(f, receipt)
        assert not valid
        return h._outcome(
            AdmissionVerdict.ALLOW,
            "RECEIPT_INTEGRITY_INVALID",
            "receipt_custody",
            evidence={"runtime_state_unchanged": True},
        )
    if attack_id == 54:
        f.release_build_ids = ("build-test", "build-receipt", "build-release")
        return h._outcome(AdmissionVerdict.HOLD, "RELEASE_IDENTITY_MISMATCH", "build_test_release_identity")
    if attack_id == 55:
        f.proof_nodes = [
            replace(node, depends_on=(*node.depends_on, "snapshot")) if node.object_id == "approval" else node
            for node in f.proof_nodes
        ]
        ok, reason = h.validate_graph(f)
        assert not ok
        return h._outcome(
            AdmissionVerdict.DENY,
            reason,
            "proof_graph",
            operational=OperationalResult.HALTED,
            engine_mode=EngineMode.HALTED,
        )
    if attack_id == 56:
        f.proof_nodes = [
            replace(node, depends_on=(*node.depends_on, node.object_id)) if node.object_id == "attestation" else node
            for node in f.proof_nodes
        ]
        ok, reason = h.validate_graph(f)
        assert not ok
        return h._outcome(
            AdmissionVerdict.DENY,
            reason,
            "proof_graph",
            operational=OperationalResult.HALTED,
            engine_mode=EngineMode.HALTED,
        )
    if attack_id == 57:
        f.proof_manifest["ordered_nodes"] = f.proof_manifest["ordered_nodes"][:-1]
        ok, reason = h.validate_graph(f)
        assert not ok
        return h._outcome(
            AdmissionVerdict.DENY,
            reason,
            "proof_graph_manifest",
            operational=OperationalResult.HALTED,
            engine_mode=EngineMode.HALTED,
        )
    if attack_id == 58:
        f.observation_contract.permitted_predicates = frozenset({"REVOKED"})
        f.observation_contract.absence_establishes = frozenset()
        _resign_contract(f)
        f.observation.proposition = "NOT_REVOKED"
        return h.admit(f).outcome
    if attack_id == 59:
        evaluation, _, activation = _activated_flow(f, h)
        _, decision = h.issue_decision(f, evaluation)
        f.flags.add("mutate_after_guard")
        return h.commit(f, evaluation, activation, decision)
    raise KeyError(f"unknown attack id: {attack_id}")


def run_positive_control() -> Outcome:
    h = AdmissionHarness()
    f = valid_fixture()
    evaluation, _, activation = _activated_flow(f, h)
    _, decision = h.issue_decision(f, evaluation)
    return h.commit(f, evaluation, activation, decision)


def run_checker_disabled_control() -> Outcome:
    h = AdmissionHarness()
    f = valid_fixture()
    f.checker_enabled = False
    return h.admit(f).outcome
