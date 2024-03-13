"""acapy-ld-signer plugin init module."""

from os import getenv

from aries_cloudagent.config.injection_context import InjectionContext
from aries_cloudagent.vc.vc_ld.external_suite import ExternalSuiteProvider
from aries_cloudagent.wallet.default_verification_key_strategy import (
    BaseVerificationKeyStrategy,
)

from .kms import KMSInterface, MiniKMS
from .provider import KMSVerificationKeyStrategy, KmsSuiteProvider


async def setup(context: InjectionContext):
    """Setup plugin."""
    KMS_BASE_URL = getenv("KMS_BASE_URL")
    if not KMS_BASE_URL:
        raise ValueError("KMS_BASE_URL not set")

    kms_client = MiniKMS(base_url=KMS_BASE_URL)
    context.injector.bind_instance(KMSInterface, kms_client)

    suite = KmsSuiteProvider(kms_client)
    context.injector.bind_instance(ExternalSuiteProvider, suite)

    key_strat = KMSVerificationKeyStrategy()
    context.injector.bind_instance(BaseVerificationKeyStrategy, key_strat)
