# -*- coding: utf-8 -*-
"""End-to-end test: agent registers with a live directory, another agent
searches and finds it, heartbeat keeps it alive."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.identity import IdentityStore
from haap.registry import RegistryServer
from haap.registry_client import register, search, heartbeat


@pytest.fixture()
def directory(tmp_path):
    rs = RegistryServer()
    http = rs.start(host="127.0.0.1", port=0)
    url = f"http://127.0.0.1:{http.server_address[1]}"
    yield url, rs
    rs.stop()


def test_full_registration_and_discovery(directory, tmp_path):
    url, _rs = directory
    business = IdentityStore(str(tmp_path / "biz")).create(
        "Peluqueria Euraka", endpoint_url=f"http://biz.example:8443/haap/messages")
    personal = IdentityStore(str(tmp_path / "pers")).create("Agente Personal")

    # the business registers itself with its speciality
    resp = register(url, business, "http://biz.example:8443/haap/messages",
                    speciality="citas-peluqueria")
    assert resp["status"] == "registered"

    # heartbeat works for a registered agent
    assert heartbeat(url, business.fingerprint)

    # the personal agent discovers it by capability
    results = search(url, capability="citas-peluqueria")
    assert len(results) == 1
    found = results[0]["agent"]
    assert found["fingerprint"] == business.fingerprint
    assert found["endpoint"] == "http://biz.example:8443/haap/messages"

    # search by free text also finds it
    results2 = search(url, q="peluqueria")
    assert len(results2) == 1
