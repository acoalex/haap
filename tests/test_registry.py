# -*- coding: utf-8 -*-
"""Tests for the federated HAAP directory (registry).

Covers: signed registration with proof-of-endpoint, search, heartbeat,
expiry, and abuse rejection (bad manifest signature, failed endpoint
proof, duplicate registration update).
"""
import base64
import json
import sys
import time
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.crypto import KeyPair
from haap.identity import IdentityStore, fingerprint_of_public_key
from haap.registry import RegistryServer, RegistryStore


def _signed_manifest(identity, endpoint="http://127.0.0.1:9999"):
    manifest = {
        "format": "haap-public-manifest-v1",
        "protocol_version": "1.0",
        "agent": {
            "fingerprint": identity.fingerprint,
            "name": identity.display_name,
            "speciality": "citas-peluqueria",
            "endpoint": endpoint,
        },
        "message_types": ["hello", "task_request", "ping"],
        "skills": [{"name": "booking", "description": "appointment booking"}],
        "tools": ["caldav"],
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode()
    sig = base64.b64encode(identity.keypair.sign(canonical)).decode()
    return manifest, sig


@pytest.fixture()
def registry(tmp_path):
    rs = RegistryServer(store=RegistryStore(entry_ttl=3600))
    http = rs.start(host="127.0.0.1", port=0)
    port = http.server_address[1]
    yield f"http://127.0.0.1:{port}", rs
    rs.stop()


def _post(url, payload):
    """POST JSON; returns (status, parsed_body). 4xx bodies are parsed,
    not raised — the tests assert on error payloads."""
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def _get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def test_registration_with_proof_of_endpoint(registry, tmp_path):
    url, rs = registry
    ident = IdentityStore(str(tmp_path / "a")).create("Agente A")
    manifest, sig = _signed_manifest(ident)
    pub_b64 = base64.b64encode(ident.keypair.public_key).decode()

    # 1. submit registration -> registry issues a signed challenge
    _, resp = _post(f"{url}/register", {
        "manifest": manifest, "public_key_b64": pub_b64,
        "manifest_signature": sig})
    assert "challenge_nonce" in resp
    nonce = resp["challenge_nonce"]

    # 2. agent signs the nonce with its private key (proof-of-endpoint)
    proof = base64.b64encode(ident.keypair.sign(nonce.encode("ascii"))).decode()
    # registry verifies the proof against the declared public key
    assert rs.store.verify_endpoint_proof(
        ident.fingerprint, nonce, pub_b64, proof)

    # 3. complete -> listed
    _, resp2 = _post(f"{url}/register/complete", {
        "fingerprint": ident.fingerprint, "manifest": manifest,
        "endpoint_proof": proof, "public_key_b64": pub_b64})
    assert resp2["status"] == "registered"

    # 4. searchable and fetchable
    found = _get(f"{url}/search?q=peluqueria")
    assert any(a["agent"]["fingerprint"] == ident.fingerprint
               for a in found["results"])
    one = _get(f"{url}/agents/{ident.fingerprint}")
    assert one["agent"]["fingerprint"] == ident.fingerprint


def test_registration_bad_signature_rejected(registry, tmp_path):
    url, rs = registry
    ident = IdentityStore(str(tmp_path / "b")).create("Agente B")
    manifest, _sig = _signed_manifest(ident)
    fake_sig = base64.b64encode(b"x" * 64).decode()
    _, resp = _post(f"{url}/register", {
        "manifest": manifest,
        "public_key_b64": base64.b64encode(ident.keypair.public_key).decode(),
        "manifest_signature": fake_sig})
    assert "error" in resp
    assert "firma" in resp["error"] or "signature" in resp["error"]


def test_registration_fingerprint_key_mismatch_rejected(registry, tmp_path):
    url, rs = registry
    ident = IdentityStore(str(tmp_path / "c")).create("Agente C")
    manifest, sig = _signed_manifest(ident)
    other = KeyPair.generate()
    _, resp = _post(f"{url}/register", {
        "manifest": manifest,
        "public_key_b64": base64.b64encode(other.public_key).decode(),
        "manifest_signature": sig})
    assert "error" in resp
    assert "does not match" in resp["error"]


def test_failed_endpoint_proof_not_listed(registry, tmp_path):
    url, rs = registry
    ident = IdentityStore(str(tmp_path / "d")).create("Agente D")
    manifest, sig = _signed_manifest(ident)
    _, resp = _post(f"{url}/register", {
        "manifest": manifest,
        "public_key_b64": base64.b64encode(ident.keypair.public_key).decode(),
        "manifest_signature": sig})
    nonce = resp["challenge_nonce"]
    # wrong proof: signed with a different key
    impostor = KeyPair.generate()
    bad_proof = base64.b64encode(impostor.sign(nonce.encode("ascii"))).decode()
    _, resp2 = _post(f"{url}/register/complete", {
        "fingerprint": ident.fingerprint, "manifest": manifest,
        "endpoint_proof": bad_proof})
    assert resp2.get("error") or resp2.get("status") != "registered"
    # verify_endpoint_proof fails with the wrong key
    assert not rs.store.verify_endpoint_proof(
        ident.fingerprint, nonce,
        base64.b64encode(ident.keypair.public_key).decode(), bad_proof)
    # and a search does not return the agent
    assert rs.store.get(ident.fingerprint) is None


def test_duplicate_registration_updates(tmp_path):
    store = RegistryStore()
    ident = IdentityStore(str(tmp_path / "e")).create("Agente E")
    manifest, sig = _signed_manifest(ident)
    pub_b64 = base64.b64encode(ident.keypair.public_key).decode()
    ok1, nonce1 = store.submit_registration(manifest, pub_b64, sig)
    assert ok1
    proof = base64.b64encode(ident.keypair.sign(nonce1.encode("ascii"))).decode()
    ok2, msg2 = store.complete_registration(ident.fingerprint, manifest, proof)
    assert ok2
    # re-register: same fingerprint -> update, not duplicate
    ok3, nonce3 = store.submit_registration(manifest, pub_b64, sig)
    assert ok3
    proof3 = base64.b64encode(ident.keypair.sign(nonce3.encode("ascii"))).decode()
    ok4, _ = store.complete_registration(ident.fingerprint, manifest, proof3)
    assert ok4
    assert store.count() == 1


def test_heartbeat_renews_and_expiry(tmp_path):
    store = RegistryStore(entry_ttl=2)  # 2 s TTL for the test
    ident = IdentityStore(str(tmp_path / "f")).create("Agente F")
    manifest, sig = _signed_manifest(ident)
    pub_b64 = base64.b64encode(ident.keypair.public_key).decode()
    ok, nonce = store.submit_registration(manifest, pub_b64, sig)
    proof = base64.b64encode(ident.keypair.sign(nonce.encode("ascii"))).decode()
    store.complete_registration(ident.fingerprint, manifest, proof)
    assert store.get(ident.fingerprint) is not None
    # heartbeat renews
    assert store.heartbeat(ident.fingerprint)
    time.sleep(0.1)
    assert store.heartbeat(ident.fingerprint)
    # without heartbeat past the TTL -> expired
    time.sleep(2.1)
    assert store.get(ident.fingerprint) is None
    assert not store.heartbeat(ident.fingerprint)


def test_search_by_capability_and_text(registry, tmp_path):
    url, rs = registry
    ident = IdentityStore(str(tmp_path / "g")).create("Agente G")
    manifest, sig = _signed_manifest(ident)
    pub_b64 = base64.b64encode(ident.keypair.public_key).decode()
    _, resp = _post(f"{url}/register", {
        "manifest": manifest, "public_key_b64": pub_b64,
        "manifest_signature": sig})
    proof = base64.b64encode(ident.keypair.sign(resp["challenge_nonce"].encode("ascii"))).decode()
    _post(f"{url}/register/complete", {
        "fingerprint": ident.fingerprint, "manifest": manifest,
        "endpoint_proof": proof, "public_key_b64": pub_b64})
    by_cap = _get(f"{url}/search?capability=caldav")
    assert len(by_cap["results"]) == 1
    by_text = _get(f"{url}/search?q=reserva")
    # 'reserva' is not in the manifest -> no match
    assert len(by_text["results"]) == 0
    by_text2 = _get(f"{url}/search?q=booking")
    assert len(by_text2["results"]) == 1
