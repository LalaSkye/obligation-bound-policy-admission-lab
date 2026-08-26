# Break the harness

The repository is designed to be attacked, but an attack counts only when it identifies a larger status than the evidence earned.

## High-value break conditions

- Obtain candidate `ALLOW` with a required predicate missing, unknown, stale, revoked or mismatched.
- Activate without the exact stage-appropriate principal, capability, grant, scope and register version.
- Make candidate failure determine incumbent or fallback standing.
- Substitute a derivation, approval, observation contract, interpretation component or executable dependency without invalidating the bound state.
- Cause the engine to execute a closure different from the one checked while preserving a successful receipt.
- Commit a governed consequence after standing expires or after any guarded state version changes.
- Route a diagnostic, preview or cached record into the commit boundary.
- Make an observation assign itself a role or upgrade absence into a negative fact without the bound contract.
- Construct a cyclic, forward-referencing, incomplete or self-referential proof graph that the verifier accepts.
- Pass an attack for the wrong typed reason.

## Add an attack

1. Start from `valid_fixture()`.
2. Mutate one relation at a time in `src/obpa_lab/scenarios.py`.
3. Add an exact oracle to `spec/attack-register.json`: admission verdict, operational result, failed predicate, typed reason, mutation/non-use expectation and engine mode.
4. Run the full suite.

A generic exception, unrelated `HOLD`, or unrelated `DENY` is not a successful defense. The test must demonstrate that the intended condition was caught.

## Report format

Include:

- attack ID or proposed successor ID;
- exact fixture mutation;
- expected and observed typed result;
- state or evidence that moved;
- why the observed result exceeds the repository claim ceiling;
- minimal reproduction.

Do not infer production impact or safety impact from this local harness without separate evidence.
