# -*- coding: utf-8 -*-
"""HAAP demo: personal agent books a hairdresser appointment at a
business agent — marketplace mode, zero human intervention.

Two full HAAP agents on this machine:
  * Peluqueria Euraka (business): publishes open booking services, its
    `on_task` callback writes the appointment into a LOCAL iCalendar file
    (stand-in for the CalDAV calendar).
  * Agente Personal: discovers availability, books, and shows the result.

Both run over real HTTP (127.0.0.1 ephemeral ports) with signed
Ed25519 envelopes end to end.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from haap.audit import AuditLog
from haap.client import HAAPClient
from haap.directory import Directory
from haap.identity import IdentityStore
from haap.server import HAAPServer
from haap.transport import HttpTransport


def main() -> None:
    data = Path(__file__).parent / "demo_data"
    data.mkdir(exist_ok=True)
    calendar_file = data / "citas_peluqueria.ics"

    # ------------------------------------------------- business agent setup
    id_biz = IdentityStore(str(data / "biz")).create("Peluqueria Euraka")
    server_biz = HAAPServer(
        id_biz, Directory(str(data / "biz")), audit=AuditLog(memory=True),
        speciality="citas-peluqueria",
        marketplace_catalog={
            "corte": {"price_eur": 15, "duration_min": 30},
            "corte+barba": {"price_eur": 22, "duration_min": 45},
        },
        marketplace_policy={"auto_accept": True, "open_hours": "10:00-19:00"})

    # the business backend: write the appointment into its calendar file
    # (in production this is the CalDAV write we built earlier)
    def write_to_calendar(task_id: str, payload: dict) -> dict:
        service = payload.get("service", "?")
        when = payload.get("when", "?")
        entry = (f"BEGIN:VEVENT\n"
                 f"SUMMARY:Cita {service} (cliente {payload.get('client_fp', 'n/a')})\n"
                 f"DTSTART:{when.replace('-', '').replace(':', '')}00Z\n"
                 f"DESCRIPTION:Reservado via HAAP marketplace\n"
                 f"END:VEVENT\n")
        with open(calendar_file, "a", encoding="utf-8") as fh:
            fh.write(entry)
        return {"estado": "reservada", "service": service, "when": when,
                "calendar": str(calendar_file.name)}

    server_biz.on_task = write_to_calendar
    http_biz = server_biz.start(host="127.0.0.1", port=0)
    port_biz = http_biz.server_address[1]
    biz_url = f"http://127.0.0.1:{port_biz}"  # base; client appends /haap/messages
    print(f"[peluqueria] agente {id_biz.fingerprint} sirviendo en {biz_url}")

    # -------------------------------------------- personal agent: discover
    id_pers = IdentityStore(str(data / "pers")).create("Agente Personal")
    client_pers = HAAPClient(id_pers, Directory(str(data / "pers")),
                             transport=HttpTransport())
    print(f"[personal ] agente {id_pers.fingerprint}")

    quote = client_pers.service_search(
        id_biz.fingerprint, biz_url, services="corte", date="2026-09-10")
    print(f"\n[personal] disponibilidad recibida: {quote['services']}")
    print(f"[personal] politica del negocio: {quote['policy']}")

    # ------------------------------------------------- personal agent: book
    result = client_pers.service_book(
        id_biz.fingerprint, biz_url,
        service="corte", when="2026-09-10T17:00")
    print(f"\n[personal] RESERVA CONFIRMADA: {result}")

    # ------------------------------------------------------------ show both
    print("\n[peluqueria] calendario de citas tras la reserva:")
    print(calendar_file.read_text())
    print("[peluqueria] audit (decisiones):")
    for e in server_biz.audit.recent(last=5):
        print(f"  {e['event']:<24} {e['friend']:<22} {e['result']}")

    server_biz.stop()
    print("\nDemo completa: dos agentes, dos identidades criptograficas, "
          "una cita reservada sin intervencion humana.")


if __name__ == "__main__":
    main()
