# -*- coding: utf-8 -*-
"""Repo-root shim so this repository is itself a Hermes plugin directory.

`hermes plugins install acoalex/haap` clones the repo into
``~/.hermes/plugins/hermes-haap/`` and imports this package; we forward to the
real plugin in ``haap/hermes_plugin``. Prefer the installed package when
``haap`` is already in the Hermes venv, otherwise import it from this checkout.
"""
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

try:
    from haap.hermes_plugin import register  # noqa: F401 - installed in the venv
except ImportError:  # pragma: no cover - drop-in checkout without pip install
    if _HERE not in sys.path:
        sys.path.insert(0, _HERE)
    from haap.hermes_plugin import register  # noqa: F401

__all__ = ["register"]
