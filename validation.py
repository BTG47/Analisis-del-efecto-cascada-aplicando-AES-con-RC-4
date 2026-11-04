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

    isPermitedType = isinstance(value, (bytes, bytearray, memoryview))

    if not isPermitedType:
        raise TypeError(f"{name} debe de ser bytes, no {type(value).__name__}")

    return bytes(value)


def require_key(key: object, size: int = KEY_SIZE) -> bytes:
    """Valida que la clave sea bytes y mida exactamente ``size`` bytes."""

    key = require_bytes(key, "key")
    # Checar si no pasa del tamaño
    if len(key) != size:
        raise ValueError(f"key debe medir exactamente {size}, no es del tamaño esperado")

    return key
