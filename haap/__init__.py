# -*- coding: utf-8 -*-
"""HAAP - Hermes Agent Alliance Protocol.

Protocolo de comunicación entre agentes Hermes en distintas máquinas:
identidad criptográfica (Ed25519), amistad con challenge-response y
aprobación humana, capacidades, permisos granulares, rate limiting,
auditoría y mensajería de tareas. Se integra en Hermes Agent como plugin
nativo (``haap.hermes_plugin``: tools, servidor en el gateway, registro en
el directorio y avisos al dueño) y también funciona como librería/CLI
independiente.
"""

__version__ = "1.0.0"
PROTOCOL_VERSION = "1.0"
__all__ = ["__version__", "PROTOCOL_VERSION"]
