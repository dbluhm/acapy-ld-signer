"""KMS Interface."""

from dataclasses import dataclass
from typing import Literal, Optional, Union

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


@dataclass
class AssociateResult:
    """Key association result."""

    kid: str
    wallet_id: str
    alias: str

    @classmethod
    def from_dict(cls, data: dict) -> "AssociateResult":
        """Create an AssociateResult from a dictionary."""
        return cls(
            kid=data["kid"],
            wallet_id=data["kid"],
            alias=data["alias"],
        )


class MiniKMS:
    """Minimal KMS for testing."""

    OMITTED = object()

    def __init__(self, base_url: str, profile: Optional[str] = None):
        """Initialize the MiniKMS."""
        self.base_url = base_url
        self.client = ClientSession(base_url=base_url)
        self.profile = profile

    async def create_profile_if_not_exists(self, profile: str):
        """Create profile if not exists."""
        async with self.client.post("/profile", json={"name": profile}) as resp:
            if not resp.ok:
                if resp.status == 400 and "json" in resp.headers.getone("Content-Type"):
                    body = await resp.json()
                    if "already exists" in body.get("detail"):
                        pass
                    else:
                        message = f"{resp.status}: {resp.reason}; {body}"
                        raise ValueError(f"Error creating profile: {message}")
                else:
                    raise ValueError(
                        f"Error creating profile: {resp.status}: {resp.reason}"
                    )
            else:
                body = await resp.json()
                if body.get("success") is not True:
                    raise ValueError("Unknown error while creating profile")

    def with_profile(self, profile: Union[str, None, object] = OMITTED) -> "MiniKMS":
        """Create a new instance with profile."""
        if profile is not self.OMITTED:
            assert isinstance(profile, str) or profile is None
            return MiniKMS(self.base_url, profile)

        return self

    def headers(self):
        """Return headers."""
        return {"X-Profile": self.profile or "default"}

    async def generate_key(self, alg: KeyAlg) -> KeyResult:
        """Generate a new key pair."""
        async with self.client.post(
            "/key/generate", headers=self.headers(), json={"alg": alg}
        ) as resp:
            if not resp.ok:
                raise ValueError(f"Error generating key: {resp.status} {resp.reason}")

            body = await resp.json()

        return KeyResult.from_dict(body)

    async def associate_key(self, kid: str, alias: str) -> AssociateResult:
        """Associate a key with additional identifiers."""
        async with self.client.post(
            f"/key/{kid}/associate", headers=self.headers(), json={"alias": alias}
        ) as resp:
            if not resp.ok:
                raise ValueError(f"Error associating key: {resp.status} {resp.reason}")

            body = await resp.json()
            return AssociateResult.from_dict(body)

    async def get_key_by_alias(self, alias: str) -> KeyResult:
        """Retrieve a key by identifiers."""
        async with self.client.get(
            "/key", headers=self.headers(), params={"alias": alias}
        ) as resp:
            if not resp.ok:
                message = f"{resp.status} {resp.reason}"
                if "json" in resp.headers.getone("Content-Type"):
                    body = await resp.json()
                    message = f"{message}; {body}"

                raise ValueError(f"Error retrieving key: {message}")

            body = await resp.json()
            return KeyResult.from_dict(body)

    async def sign(self, kid: str, data: bytes) -> bytes:
        """Sign a message with the private key."""
        data_enc = bytes_to_b64(data, urlsafe=True, pad=True)
        async with self.client.post(
            "/sign", headers=self.headers(), json={"kid": kid, "data": data_enc}
        ) as resp:
            if not resp.ok:
                raise ValueError(f"Error signing message: {resp.status} {resp.reason}")
            body = await resp.json()
            sig_data = b64_to_bytes(body["sig"], urlsafe=True)

        return sig_data
