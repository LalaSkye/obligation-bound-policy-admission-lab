from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


@dataclass
class DemoKeyring:
    """Deterministic Ed25519 keys for reproducible local attack fixtures.

    The seeds are fixture material, not production secrets or an external PKI.
    """

    _private: dict[str, Ed25519PrivateKey] = field(default_factory=dict)

    def _key(self, principal: str) -> Ed25519PrivateKey:
        if principal not in self._private:
            seed = hashlib.sha256(("obpa-demo-key:" + principal).encode()).digest()
            self._private[principal] = Ed25519PrivateKey.from_private_bytes(seed)
        return self._private[principal]

    def sign(self, principal: str, content_digest: str) -> str:
        return self._key(principal).sign(content_digest.encode("ascii")).hex()

    def verify(self, principal: str, content_digest: str, signature: str) -> bool:
        try:
            self._key(principal).public_key().verify(bytes.fromhex(signature), content_digest.encode("ascii"))
            return True
        except (InvalidSignature, ValueError):
            return False
