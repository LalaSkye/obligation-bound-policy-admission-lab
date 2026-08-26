# Obligation-Bound Policy Admission Lab v0.6

This repository is a local, single-engine, single-writer reference harness for a narrow question:

> Can a candidate policy become active and govern a declared consequence only while the exact, current, register-relative evidence required by the harness remains established?

The harness makes that question executable. It binds policy identity, upstream obligation identity, typed authority grants, the declared derivation and approval records, external-observation contracts, the checked-to-executed interpretation chain, the active engine slot, and the final commit guard. It then runs a frozen 59-attack register against those boundaries.

## What it establishes

Within this declared harness, the implementation can establish bounded identity, provenance, currentness, and transition facts relative to declared trusted inputs. It can refuse activation or consequence when a required proposition, interpretation, authority grant, state, or freshness relation is missing or invalid.

It does **not** establish:

- that the originating obligation is morally, legally, or substantively correct;
- that the declared authority register was legitimately constituted outside the harness;
- that a derivation is substantively warranted merely because its attestation is valid;
- global non-bypassability, production readiness, or safety;
- that an intact receipt is equivalent to observed engine state.

No result type in this repository contains `SAFE`.

## State discipline

These are distinct predicates. No status is inferred from another except through an explicit transition or revalidation rule:

- `AdmittedAt(P, t0)` — a historical event;
- `Standing(P, S_t)` — a current relation under a bound decision state;
- `Active(P, E_t)` — an observed engine fact.

Historical admission is not a temporal passport. Candidate failure supplies no incumbent verdict. An incumbent or fallback must independently re-establish current standing.

## Run

From the repository root:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

The suite contains 62 tests in total: 59 named attack tests, two harness controls, and one register-integrity test asserting that the frozen attack IDs are exactly 1 through 59. Each attack checks its intended predicate and typed reason; an unrelated `HOLD` or `DENY` does not pass.

To emit a machine-readable run receipt:

```bash
PYTHONPATH=src python -m obpa_lab.cli run --output artifacts/test-run-local.json
```

Verify the checked-in local release manifest:

```bash
python scripts/verify_manifest.py artifacts/release-manifest-v0.6.json
```

## Frozen sources

The exact source digests and attack-range inheritance are recorded in [`spec/source-lock.json`](spec/source-lock.json). The executable attack definitions are in [`spec/attack-register.json`](spec/attack-register.json). A semantic change requires a named successor; passing tests cannot silently redefine the floor.

## Scope

- One in-memory engine instance.
- One policy slot.
- A serialized compare-and-swap activation boundary.
- One declared governed commit boundary.
- No network access or external deployment is exercised by the test harness.
- Licensing and deployment remain separate decisions.

## Provenance

- Engineering artefact, implementation and tests: **Ricky Jones**.
- Methodological review and corrections: **Sandra Škrinjar**.
- Review does not imply co-authorship, shared ownership or merger of the engineering artefact.

The exact proposed announcement is frozen in [`PUBLIC_POST.md`](PUBLIC_POST.md) for release review.
