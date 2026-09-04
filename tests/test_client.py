# -*- coding: utf-8 -*-
"""End-to-end tests for HAAPClient: full friendship + task delegation
between two complete agents (server + client) over MemoryTransport."""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.audit import AuditLog
from haap.client import HAAPClient
from haap.directory import Directory
from haap.errors import PermissionDeniedError
from haap.identity import IdentityStore
from haap.server import HAAPServer
from haap.transport import MemoryTransport


@pytest.fixture()
def pair(tmp_path):
    """Personal agent (A) + business agent (B), each with server+client."""
    id_a = IdentityStore(str(tmp_path / "a")).create("Agente Personal")
    id_b = IdentityStore(str(tmp_path / "b")).create(
        "Peluqueria", endpoint_url="http://biz.example:8443/haap/messages")

    server_b = HAAPServer(id_b, Directory(str(tmp_path / "b")),
                          audit=AuditLog(memory=True),
                          speciality="citas-peluqueria")
    client_a = HAAPClient(id_a, Directory(str(tmp_path / "a")),
                          audit=AuditLog(memory=True))
    # wire: client_a sends -> server_b router
    client_a.transport = MemoryTransport(lambda env, url: server_b.handle_message(env))
    return id_a, id_b, server_b, client_a


def _pub(ident):
    return base64.b64encode(ident.keypair.public_key).decode()


def test_full_friendship_and_booking_flow(pair):
    id_a, id_b, server_b, client_a = pair

    # A starts the friendship with B (bootstrap carries A's public key)
    client_a.start_friendship(
        id_b.fingerprint, _pub(id_b),
        endpoint="http://biz.example:8443/haap/messages",
        name="Agente Personal", speciality="asistente-personal")
    # B now has A as pending_in
    assert server_b.directory.get(id_a.fingerprint).status == "pending_in"
    assert client_a.directory.get(id_b.fingerprint).status == "pending_out"

    # HUMAN approval on B's side, with booking permission
    server_b.directory.approve(
        id_a.fingerprint,
        grant={"task:submit": {"allow": True, "scopes": ["booking:*"]}})

    # B notifies A (as the real server does): A consolidates to accepted.
    # In production this friend_accept envelope arrives at A's SERVER and
    # its router calls directory.mark_outbound_accepted; here we simulate
    # the local state change on A's side (same code path):
    client_a.directory.mark_outbound_accepted(
        id_b.fingerprint,
        their_endpoints=["http://biz.example:8443/haap/messages"])
    assert client_a.directory.get(id_b.fingerprint).status == "accepted"

    # B's side must also know the friendship is accepted: already done by approve.
    # Simulate the business agent's booking callback (its CalDAV write):
    citas = {}
    def booking_executor(task_id, payload):
        citas[task_id] = payload["prompt"]
        return {"cita": "jueves 17:00", "estado": "reservada",
                "calendario": "acoalex@gmail.com"}
    server_b.on_task = booking_executor

    # A delegates the booking task
    result = client_a.delegate_task(
        id_b.fingerprint, "Reservar corte jueves 17:00",
        action="task:submit", resource="booking:peluqueria-euraka")
    assert result["state"] == "completed"
    assert result["detail"]["estado"] == "reservada"
    assert result["detail"]["cita"] == "jueves 17:00"
    assert len(citas) == 1

    # both sides have the task recorded
    assert len(client_a.tasks) == 1
    assert len(server_b.tasks) == 1


def test_local_guard_blocks_disallowed_action(pair):
    id_a, id_b, server_b, client_a = pair
    # establish friendship with an EMPTY permission matrix on A's side
    # (the add_pending_out default template grants task:submit, so we
    # override it explicitly to test the deny-by-default guard)
    client_a.directory.add_pending_out(
        id_b.fingerprint, _pub(id_b), "B",
        endpoints=["http://biz.example:8443/haap/messages"],
        permissions={})
    client_a.directory.mark_outbound_accepted(id_b.fingerprint)
    server_b.directory.register_known(
        id_a.fingerprint, _pub(id_a), name="A")
    server_b.directory.approve(id_a.fingerprint,
                               grant={"task:submit": {"allow": True, "scopes": ["*"]}})
    # A's local matrix for B has NO task:submit -> local guard fires first
    with pytest.raises(PermissionDeniedError):
        client_a.delegate_task(id_b.fingerprint, "Reservar algo")


def test_refresh_endpoint_validates_fingerprint(pair, monkeypatch):
    id_a, id_b, server_b, client_a = pair
    client_a.directory.add_pending_out(id_b.fingerprint, _pub(id_b), "B",
                                       endpoints=["http://biz.example:8443/haap/messages"])
    # well-known returns a DIFFERENT fingerprint -> must raise
    import haap.client as client_mod
    monkeypatch.setattr(client_mod, "_fetch_json", lambda url, timeout=10.0: {
        "agent": {"fingerprint": "HF-0000000000000000",
                  "endpoint": "http://evil.example:9/haap/messages"}})
    from haap.errors import DiscoveryError
    with pytest.raises(DiscoveryError):
        client_a.refresh_endpoint(id_b.fingerprint)


def test_refresh_endpoint_accepts_matching_fingerprint(pair, monkeypatch):
    id_a, id_b, server_b, client_a = pair
    client_a.directory.add_pending_out(id_b.fingerprint, _pub(id_b), "B",
                                       endpoints=["http://old.example:1/haap/messages"])
    import haap.client as client_mod
    monkeypatch.setattr(client_mod, "_fetch_json", lambda url, timeout=10.0: {
        "agent": {"fingerprint": id_b.fingerprint,
                  "endpoint": "http://biz.example:8443"}})
    url = client_a.refresh_endpoint(id_b.fingerprint)
    assert url == "http://biz.example:8443/haap/messages"
    assert client_a.directory.get(id_b.fingerprint).endpoints[0] == url
