# -*- coding: utf-8 -*-
"""HAAP command-line interface.

Subcommands:
  init                 create the local agent identity
  whoami               show local identity (fingerprint, name, endpoint)
  friends list         list known friends and their status
  friends add          start an outbound friend request
  friends approve      approve an inbound friend request (HUMAN decision)
  friends deny         reject an inbound friend request
  friends remove       delete a relationship
  friends block        block a fingerprint entirely
  capabilities show    display the local capability manifest
  task send            delegate a task to a friend
  task list            list local tasks
  serve                run the HAAP messaging server
  registry serve       run a federated public directory
  registry register    register this agent with a directory
  registry search      search a directory for agents by capability
  audit                show recent audit entries

Identity/data directory: $HAAP_DIR (default ~/.haap).
"""
from __future__ import annotations

import argparse
import base64
import json
import sys

from . import __version__
from . import envelope as env_mod
from .audit import AuditLog
from .crypto import b64e
from .directory import Directory
from .errors import HAAPError
from .identity import IdentityStore
from .server import HAAPServer
from .tasks import TaskRegistry


def _store(args) -> IdentityStore:
    return IdentityStore(getattr(args, "dir", None))


def _load_identity(args):
    return _store(args).load()


# --------------------------------------------------------------------- init
def cmd_init(args) -> int:
    store = _store(args)
    if store.exists():
        print(f"identity already exists at {store.path}")
        return 1
    ident = store.create(display_name=args.name, endpoint_url=args.endpoint or "")
    print(f"identity created: {ident.fingerprint} ({ident.display_name})")
    print(f"stored at {store.path} (permissions 0600)")
    return 0


def cmd_whoami(args) -> int:
    ident = _load_identity(args)
    print(json.dumps(ident.public_claims(), indent=2))
    return 0


# ------------------------------------------------------------------ friends
def cmd_friends(args) -> int:
    directory = Directory(getattr(args, "dir", None))
    if args.friends_command == "list":
        recs = directory.all()
        if not recs:
            print("(no friends)")
            return 0
        for r in recs:
            print(f"{r.fingerprint}  {r.status:<12} {r.name:<24} "
                  f"endpoints={len(r.endpoints)}")
        return 0
    if args.friends_command == "requests":
        pending = directory.by_status("pending_in")
        if not pending:
            print("(no pending friend requests)")
            return 0
        from .roles import load_roles
        roles = load_roles(getattr(args, "dir", None))
        for r in pending:
            caps = r.declared_capabilities or {}
            print(f"{r.fingerprint}  {r.name}")
            print(f"  message:    {r.notes}")
            print(f"  speciality: {caps.get('speciality', '(none)')}")
            print(f"  decide:     haap friends approve {r.fingerprint} --role "
                  f"[{'|'.join(sorted(roles))}]")
        return 0
    if args.friends_command == "roles":
        from .roles import role_summary
        print(role_summary(getattr(args, "dir", None)))
        return 0
    if args.friends_command == "add":
        rec = directory.add_pending_out(args.fingerprint, args.public_key,
                                        args.name or args.fingerprint,
                                        endpoints=[args.endpoint] if args.endpoint else None)
        print(f"pending_out: {rec.fingerprint} ({rec.name})")
        return 0
    if args.friends_command == "approve":
        grant = json.loads(args.grant) if args.grant else None
        rate_limits = None
        if args.role:
            from .roles import resolve_role
            _, spec = resolve_role(args.role, getattr(args, "dir", None))
            grant = grant or dict(spec.get("permissions") or {})
            rate_limits = dict(spec.get("rate_limits") or {})
        rec = directory.approve(args.fingerprint, grant=grant,
                                rate_limits=rate_limits)
        granted = ", ".join(sorted(rec.permissions)) or "(none)"
        print(f"accepted: {rec.fingerprint} as role '{args.role or 'custom'}'")
        print(f"granted actions: {granted}")
        return 0
    if args.friends_command == "deny":
        directory.deny(args.fingerprint)
        print(f"denied and removed: {args.fingerprint}")
        return 0
    if args.friends_command == "remove":
        directory.remove(args.fingerprint)
        print(f"removed: {args.fingerprint}")
        return 0
    if args.friends_command == "block":
        directory.block(args.fingerprint)
        print(f"blocked: {args.fingerprint}")
        return 0
    print("unknown friends subcommand")
    return 1


# ------------------------------------------------------------- capabilities
def cmd_capabilities(args) -> int:
    from .capabilities import build_manifest
    ident = _load_identity(args)
    manifest = build_manifest(ident.public_claims(),
                              speciality=args.speciality or "")
    if args.show_all:
        print(json.dumps(manifest, indent=2, ensure_ascii=False))
    else:
        agent = manifest["agent"]
        print(f"{agent.get('fingerprint')}  {agent.get('display_name')}")
        print(f"skills: {len(manifest['skills'])}  tools: {len(manifest['tools'])}")
    return 0


# -------------------------------------------------------------------- tasks
def cmd_task(args) -> int:
    tasks = TaskRegistry(getattr(args, "dir", None))
    if args.task_command == "list":
        recs = tasks.list(role=args.role or "", friend=args.friend or "")
        if not recs:
            print("(no tasks)")
            return 0
        for t in recs:
            print(f"{t.task_id}  {t.state:<10} {t.role:<9} "
                  f"{t.friend_fingerprint}  {t.prompt[:40]}")
        return 0
    if args.task_command == "send":
        raise HAAPError(
            "task send requires a running friend server; use the Python API "
            "(server.py + transport.py) — CLI delegation lands with client.py")
    return 1


# -------------------------------------------------------------------- serve
def cmd_serve(args) -> int:
    ident = _load_identity(args)
    directory = Directory(getattr(args, "dir", None))
    audit = AuditLog(getattr(args, "dir", None))
    server = HAAPServer(ident, directory, audit=audit, speciality=args.speciality)
    http = server.start(host=args.host, port=args.port)
    print(f"HAAP server {ident.fingerprint} listening on "
          f"{args.host}:{http.server_address[1]}")
    print("endpoints: POST /haap/messages | GET /.well-known/haap.json | GET /health")
    print("Ctrl+C to stop")
    try:
        while True:
            import time as _t
            _t.sleep(3600)
    except KeyboardInterrupt:
        server.stop()
        print("server stopped")
    return 0


# ----------------------------------------------------------------- registry
def cmd_registry(args) -> int:
    from .registry import RegistryServer
    if args.registry_command == "serve":
        rs = RegistryServer()
        http = rs.start(host=args.host, port=args.port)
        print(f"HAAP directory {rs.fingerprint} listening on "
              f"{args.host}:{http.server_address[1]}")
        try:
            while True:
                import time as _t
                _t.sleep(3600)
        except KeyboardInterrupt:
            rs.stop()
            print("directory stopped")
        return 0
    if args.registry_command == "register":
        from .registry_client import register
        ident = _load_identity(args)
        endpoint = args.endpoint or ident.endpoint_url
        if not endpoint:
            raise HAAPError(
                "no endpoint declared: pass --endpoint or set it at haap init")
        resp = register(args.registry, ident, endpoint,
                        speciality=args.speciality or "")
        print(f"registered at {args.registry}: {resp.get('status')}")
        return 0
    if args.registry_command == "search":
        from .registry_client import search
        results = search(args.registry, capability=args.capability or "",
                         q=args.query or "")
        if not results:
            print("(no results)")
            return 0
        for m in results:
            a = m.get("agent") or {}
            print(f"{a.get('fingerprint')}  {a.get('speciality', ''):<24} "
                  f"{a.get('name', '')}  {a.get('endpoint', '')}")
        return 0
    return 1


# -------------------------------------------------------------------- audit
def cmd_audit(args) -> int:
    audit = AuditLog(getattr(args, "dir", None))
    for e in audit.recent(last=args.last, friend=args.friend or ""):
        print(f"{e['ts']:.0f}  {e['event']:<24} {e['friend']:<22} {e['result']}")
    return 0


# ------------------------------------------------------------------ parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="haap",
                                description="Hermes Agent Alliance Protocol")
    p.add_argument("--version", action="version", version=f"haap {__version__}")
    p.add_argument("--dir", default=None, help="HAAP data directory (default $HAAP_DIR or ~/.haap)")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("init", help="create the local identity")
    sp.add_argument("--name", default="hermes-agent")
    sp.add_argument("--endpoint", default="", help="public messaging URL")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("whoami", help="show local identity")
    sp.set_defaults(func=cmd_whoami)

    sp = sub.add_parser("friends", help="manage friendships")
    sp.add_argument("friends_command", choices=["list", "requests", "add", "approve",
                                                "deny", "remove", "block", "roles"])
    sp.add_argument("fingerprint", nargs="?", default="")
    sp.add_argument("--public-key", default="", help="friend's public key (b64)")
    sp.add_argument("--name", default="")
    sp.add_argument("--endpoint", default="")
    sp.add_argument("--grant", default=None, help="JSON permission matrix (approve)")
    sp.add_argument("--role", default="", help="named role template (approve)")
    sp.set_defaults(func=cmd_friends)

    sp = sub.add_parser("capabilities", help="show the capability manifest")
    sp.add_argument("--speciality", default="")
    sp.add_argument("--show-all", action="store_true")
    sp.set_defaults(func=cmd_capabilities)

    sp = sub.add_parser("task", help="task operations")
    sp.add_argument("task_command", choices=["list", "send"])
    sp.add_argument("--role", default="", help="filter: delegate|submit")
    sp.add_argument("--friend", default="", help="filter by friend fingerprint")
    sp.set_defaults(func=cmd_task)

    sp = sub.add_parser("serve", help="run the messaging server")
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8443)
    sp.add_argument("--speciality", default="")
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("registry", help="federated directory operations")
    sp.add_argument("registry_command", choices=["serve", "register", "search"])
    sp.add_argument("--host", default="0.0.0.0")
    sp.add_argument("--port", type=int, default=8444)
    sp.add_argument("--registry", default="", help="directory URL (register/search)")
    sp.add_argument("--endpoint", default="", help="your public messaging URL (register)")
    sp.add_argument("--speciality", default="", help="your speciality tag (register)")
    sp.add_argument("--capability", default="", help="capability filter (search)")
    sp.add_argument("--query", "--q", dest="query", default="", help="free-text filter (search)")
    sp.set_defaults(func=cmd_registry)

    sp = sub.add_parser("audit", help="recent audit entries")
    sp.add_argument("--last", type=int, default=30)
    sp.add_argument("--friend", default="")
    sp.set_defaults(func=cmd_audit)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except HAAPError as exc:
        print(f"HAAP error [{getattr(exc, 'code', 'HAAP_ERROR')}]: {exc}",
              file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
