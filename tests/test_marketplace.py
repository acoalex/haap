# -*- coding: utf-8 -*-
"""Marketplace mode tests: open service discovery/booking WITHOUT prior
friendship — signed client identity, business policy, rate limits."""
import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap import envelope as env_mod
from haap.audit import AuditLog
from haap.directory import Directory
from haap.identity import IdentityStore
from haap.rate_limiter import RateLimiter
from haap.server import HAAPServer


@pytest.fixture()
def business(tmp_path):
    """A hair-salon agent publishing an open booking catalog."""
    id_biz = IdentityStore(str(tmp_path / "biz")).create(
        "Peluqueria Euraka", endpoint_url="http://biz.example:8443/haap/messages")
    server = HAAPServer(
        id_biz, Directory(str(tmp_path / "biz")), audit=AuditLog(memory=True),
        speciality="citas-peluqueria",
        marketplace_catalog={
            "corte": {"price_eur": 15, "duration_min": 30},
            "corte+barba": {"price_eur": 22, "duration_min": 45},
        },
        marketplace_policy={"auto_accept": True, "open_hours": "10:00-19:00"})
    return id_biz, server


def _signed_mp(identity, recipient_fp, message_type, payload):
    """Sign a marketplace envelope: the sender's public key always travels
    in the payload (self-contained bootstrap verification)."""
    payload = dict(payload)
    payload["public_key_b64"] = base64.b64encode(
        identity.keypair.public_key).decode()
    return env_mod.sign_body(identity, message_type, recipient_fp, payload)


def test_service_search_returns_catalog(business, tmp_path):
    id_biz, server = business
    client = IdentityStore(str(tmp_path / "c")).create("Cliente")
    env = _signed_mp(client, id_biz.fingerprint, "service_search",
                     {"services": "corte", "date": "2026-09-10"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "service_quote"
    assert reply["payload"]["available"] is True
    assert "corte" in reply["payload"]["services"]


def test_service_book_with_auto_accept(business, tmp_path):
    id_biz, server = business
    client = IdentityStore(str(tmp_path / "c")).create("Cliente")
    executed = {}
    server.on_task = lambda tid, payload: executed.update({tid: payload}) or {
        "cita": "2026-09-10 17:00", "estado": "reservada"}
    env = _signed_mp(client, id_biz.fingerprint, "service_book",
                     {"service": "corte", "when": "2026-09-10T17:00"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "task_result"
    assert reply["payload"]["state"] == "completed"
    assert reply["payload"]["detail"]["status"] == "reserved"
    assert reply["payload"]["detail"]["cita"] == "2026-09-10 17:00"
    assert executed  # the business backend (CalDAV) was called


def test_service_book_rejected_without_auto_accept(tmp_path):
    id_biz = IdentityStore(str(tmp_path / "biz")).create("Peluqueria")
    server = HAAPServer(id_biz, Directory(str(tmp_path / "biz")),
                        audit=AuditLog(memory=True),
                        marketplace_policy={"auto_accept": False})
    client = IdentityStore(str(tmp_path / "c")).create("Cliente")
    env = _signed_mp(client, id_biz.fingerprint, "service_book",
                     {"service": "corte", "when": "x"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "error"
    assert "auto_accept" in reply["payload"]["detail"]


def test_marketplace_rate_limit(tmp_path):
    id_biz = IdentityStore(str(tmp_path / "biz")).create("Peluqueria")
    server = HAAPServer(id_biz, Directory(str(tmp_path / "biz")),
                        audit=AuditLog(memory=True),
                        marketplace_policy={"auto_accept": True})
    client = IdentityStore(str(tmp_path / "c")).create("Cliente")
    codes = []
    for i in range(12):  # marketplace bucket capacity is 10
        env = _signed_mp(client, id_biz.fingerprint, "service_search",
                         {"services": "corte"})
        r = server.handle_message(env)
        codes.append(r["message_type"])
    assert codes.count("error") >= 1  # eventually limited
    assert codes[:9].count("service_quote") >= 8  # first ones pass


def test_blocked_sender_cannot_use_marketplace(tmp_path):
    id_biz = IdentityStore(str(tmp_path / "biz")).create("Peluqueria")
    server = HAAPServer(id_biz, Directory(str(tmp_path / "biz")),
                        audit=AuditLog(memory=True),
                        marketplace_policy={"auto_accept": True})
    client = IdentityStore(str(tmp_path / "c")).create("Cliente")
    server.directory.block(client.fingerprint)
    env = _signed_mp(client, id_biz.fingerprint, "service_search",
                     {"services": "corte"})
    reply = server.handle_message(env)
    assert reply["message_type"] == "error"
    assert reply["payload"]["error_code"] == "PERMISSION_DENIED"
