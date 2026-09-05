# Changelog

Todos los cambios notables de HAAP se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

## [1.2.0] - 2026-09-05

### Añadido
- **Servidor MCP** (`haap/mcp_server.py`, CLI `haap mcp [--serve]`): las tools
  `haap_*` por stdio JSON-RPC para Hermes (`mcp_servers`), Claude Code, Cursor…
  `initialize`/`ping`/`tools/list`/`tools/call`; fallos de tool como `isError`.
- `haap/tools.py`: superficie de tools compartida (runtime, schemas, handlers)
  de la que beben el plugin de Hermes y el servidor MCP — una implementación,
  dos fachadas.
- `WebhookNotifier` firma por defecto en el formato genérico **V2 de Hermes**
  (`X-Webhook-Signature-V2` + `X-Webhook-Timestamp`, anti-replay); `fmt="legacy"`
  conserva `X-HAAP-Signature`. El plugin acepta `webhook_url`/`webhook_secret`.
- Tests: webhook (5) y MCP (6). Suite: 63.

### Cambiado
- `haap.hermes_plugin` refactorizado sobre `haap.tools` (misma API pública).
- Versión del paquete alineada con este changelog (1.2.0).

## [1.1.0] - 2026-09-05

### Añadido
- **Plugin nativo de Hermes Agent** (`haap/hermes_plugin`, entry point
  `hermes_agent.plugins` → `hermes-haap`; `plugin.yaml` + shim raíz para
  `hermes plugins install acoalex/haap`): tools `haap_*` (whoami, friends,
  add_friend, delegate_task, service_search/book, registry_search/register),
  servidor HAAP arrancado en `gateway:startup`, identidad auto-creada,
  registro en el directorio + `HeartbeatLoop`, tarjetas de solicitud de
  amistad inyectadas en el chat del dueño, comando `/haap`, subcomandos
  `hermes haap …` y skill `haap`. Configuración en
  `plugins.entries.hermes-haap` o `HAAP_HERMES_*`.
- 11 tests del plugin con un `FakeCtx` (sin necesidad de Hermes).

### Cambiado
- README (ES/EN): la instalación recomendada pasa a ser el plugin; la vía
  librería + `haap serve` queda como instalación manual.
- Docstring de `haap/__init__.py` alineada con la integración real.

## [0.1.0] - 2026-09-04

### Añadido
- Núcleo criptográfico: identidad Ed25519 con fingerprint `HF-<16 hex>`.
- Envelope firmado sobre JSON canónico determinista (floats prohibidos).
- Ventana de timestamp ±300 s y anti-replay por nonce con poda perezosa.
- Módulos base: permissions (deny-by-default), rate_limiter (token bucket),
  audit (append-only), directory (estados de amistad), capabilities (manifest),
  tasks (ciclo de vida estilo A2A), transport, errors.
- Fix crítico en `canonical_json`: un `+ b"}"` en línea propia era una
  expresión de sentencia independiente y el JSON canónico salía sin la
  llave de cierre (todo envelope serializado era inválido).
