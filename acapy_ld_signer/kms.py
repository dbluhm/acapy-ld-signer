"""KMS Interface."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Literal

from aiohttp import ClientSession
from aries_cloudagent.wallet.util import b64_to_bytes, bytes_to_b64


KeyAlg = Literal[
    "ed25519",
    "x25519",
    "p256",
    "p384",
    "p521",
    "secp256k1",
    "bls12-381g1",
    "bls12-381g2",
]


@dataclass
class KeyResult:
    """Key generation result."""

    kid: str
    jwk: dict
    b58: str

    @classmethod
    def from_dict(cls, data: dict) -> "KeyResult":
        """Create a KeyResult from a dictionary."""
        return cls(
            kid=data["kid"],
            jwk=data["jwk"],
            b58=data["b58"],
        )


class KMSInterface(ABC):
    """KMS Interface."""

    @abstractmethod
    async def generate_key(self, alg: KeyAlg) -> KeyResult:
        """Generate a new key pair."""

    @abstractmethod
    async def sign(self, kid: str, data: bytes) -> bytes:
        """Sign a message with the private key."""


class MiniKMS(KMSInterface):
    """Minimal KMS for testing."""

    def __init__(self, base_url: str):
        """Initialize the MiniKMS."""
        self.client = ClientSession(base_url=base_url)

    async def generate_key(self, alg: KeyAlg) -> KeyResult:
        """Generate a new key pair."""
        async with self.client.post("/key/generate", json={"alg": alg}) as resp:
            if not resp.ok:
                raise ValueError(f"Error generating key: {resp.status} {resp.reason}")

            body = await resp.json()

        return KeyResult.from_dict(body)

    async def sign(self, kid: str, data: bytes) -> bytes:
        """Sign a message with the private key."""
        data_enc = bytes_to_b64(data, urlsafe=True, pad=True)
        async with self.client.post(
            "/sign", json={"kid": kid, "data": data_enc}
        ) as resp:
            if not resp.ok:
                raise ValueError(f"Error signing message: {resp.status} {resp.reason}")
            body = await resp.json()
            sig_data = b64_to_bytes(body["sig"], urlsafe=True)

        return sig_data
