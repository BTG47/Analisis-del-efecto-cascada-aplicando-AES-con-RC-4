"""Validaciones compartidas por la API pública.

Contrato de errores del módulo (ver docs/DECISIONS.md):

- Tipo incorrecto  -> TypeError
- Clave de largo incorrecto -> ValueError
- Padding inválido -> ValueError
"""

KEY_SIZE = 32


def require_bytes(value: object, name: str = "data") -> bytes:
    """Devuelve ``value`` convertido a ``bytes`` o lanza ``TypeError``.

    Se aceptan los tipos "bytes-like": ``bytes``, ``bytearray`` y ``memoryview``.
    Cualquier otra cosa (``str`` incluido) es un error de tipo.
    """
    # TODO Misión 1
    # - isinstance(value, (bytes, bytearray, memoryview)) -> bytes(value)
    # - si no, TypeError con un mensaje que diga qué se recibió.
    raise NotImplementedError("Misión 1: require_bytes")


def require_key(key: object, size: int = KEY_SIZE) -> bytes:
    """Valida que la clave sea bytes y mida exactamente ``size`` bytes."""
    # TODO Misión 1
    # - Reutilizar require_bytes.
    # - Si el largo no coincide, ValueError indicando esperado y recibido.
    # - Devolver los bytes ya normalizados (no None).
    raise NotImplementedError("Misión 1: require_key")
