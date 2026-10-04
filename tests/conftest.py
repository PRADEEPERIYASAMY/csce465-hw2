import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import handshake as hs  # noqa: E402


@pytest.fixture(scope="session")
def params():
    return hs.load_group()


@pytest.fixture(scope="session")
def rsa_keys():
    # 3072-bit RSA keygen is slow; generate once per test run.
    return {"gateway": hs.generate_identity_key(),
            "node": hs.generate_identity_key(),
            "mallory": hs.generate_identity_key()}


@pytest.fixture
def pair(params, rsa_keys):
    return hs.make_pair(params, rsa_keys["gateway"], rsa_keys["node"])
