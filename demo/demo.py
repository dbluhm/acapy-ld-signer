"""Demo script."""

import asyncio
from dataclasses import dataclass
from os import getenv

from controller import Controller
from controller.logging import logging_to_stdout, section

AGENT = getenv("AGENT", "http://issuer:3001")


@dataclass
class DIDCreateResponse:
    """Response to a DID Create request."""

    did: str
    verkey: str
    posture: str
    method: str
    key_type: str


async def main():
    """Run the demo."""
    async with Controller(AGENT) as agent:
        with section("Create issuing DID"):
            did_info = await agent.post("/ext/did/create", response=DIDCreateResponse)

        with section("Issue an Example Cred"):
            await agent.post(
                "/vc/credentials/issue",
                json={
                    "credential": {
                        "@context": [
                            "https://www.w3.org/2018/credentials/v1",
                            "https://w3id.org/citizenship/v1",
                        ],
                        "type": ["VerifiableCredential", "PermanentResident"],
                        "issuer": did_info.did,
                        "issuanceDate": "2020-01-01T19:23:24Z",
                        "credentialSubject": {
                            "type": ["PermanentResident"],
                            "id": "did:example:bob",
                            "givenName": "Bob",
                            "familyName": "Builder",
                            "gender": "Male",
                            "birthCountry": "Bahamas",
                            "birthDate": "1958-07-17",
                        },
                    },
                    "options": {
                        "type": "Ed25519Signature2020",
                        "challenge": "abc",
                        "domain": "http://example.com",
                    },
                },
            )


if __name__ == "__main__":
    logging_to_stdout()
    asyncio.run(main())
