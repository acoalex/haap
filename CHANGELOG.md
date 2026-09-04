# Changelog

Todos los cambios notables de HAAP se documentan aquí.
Formato basado en [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/).

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
