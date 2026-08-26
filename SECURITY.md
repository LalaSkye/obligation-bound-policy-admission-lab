# Security and evidence policy

This is a bounded reference harness, not a deployed authorization service.

Please report reproducible cases where the implementation:

- admits, activates or commits beyond the declared proof floor;
- confuses `HOLD`, `DENY` and operational integrity failures;
- accepts stale, self-authorising or wrong-source evidence;
- permits historical status to function as continuing authority;
- allows proof-object cycles, substitutions or digest drift;
- commits after the final guarded state has changed.

The deterministic Ed25519 keys are fixture keys. They exist to test content/signature binding and are not a production trust system.

This public-release candidate has not yet been published. Its attribution is limited to the exact provenance stated in the README and does not imply co-authorship.
