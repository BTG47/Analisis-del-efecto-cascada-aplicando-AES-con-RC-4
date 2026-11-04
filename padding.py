"""Relleno PKCS#7 para AES (bloque de 16 bytes).

Reglas:

- Se agregan SIEMPRE entre 1 y ``block_size`` bytes, nunca cero.
- Cada byte agregado vale exactamente la cantidad de bytes agregados.
- Si ``len(data)`` ya es múltiplo de ``block_size``, se agrega un bloque ENTERO.
- Al quitar se valida TODA la cola, no solo el último byte.

Ejemplos con block_size = 16:

    b""             -> 16 bytes 0x10
    b"A" * 15       -> 15 bytes + 0x01
    b"A" * 16       -> 16 bytes + 16 bytes 0x10  (32 en total)
"""

from validation import require_bytes

BLOCK_SIZE = 16
MAX_BLOCK_SIZE = 255  # el largo del relleno se guarda en un solo byte


def _require_block_size(block_size: object) -> int:
    """Valida el tamaño de bloque: entero entre 1 y ``MAX_BLOCK_SIZE``."""
    if not isinstance(block_size, int):
        raise TypeError(
            f"block_size debe ser int, no {type(block_size).__name__}"
        )
    if not 1 <= block_size <= MAX_BLOCK_SIZE:
        raise ValueError(
            f"block_size debe estar entre 1 y {MAX_BLOCK_SIZE}, se recibió {block_size}"
        )
    return block_size


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Agrega relleno PKCS#7 a ``data``."""
    block_size = _require_block_size(block_size)
    data = require_bytes(data)

    # obtener los bytes faltantes
    n = block_size - (len(data) % block_size)
    padding = bytes([n]) * n

    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Quita y valida el relleno PKCS#7 de ``data``."""
    data = require_bytes(data)
    block_size = _require_block_size(block_size)

    if not data or len(data) % block_size != 0:
        raise ValueError(f"El tamaño de data ({len(data)}) debe ser múltiplo de block size ({block_size})")

    n = data[-1]
    if n == 0 or n > block_size:
        raise ValueError("N no se encuentra dentro del rango esperado (1 <= data <= block_size)")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Error, los datos de n no coinciden con los esperados")

    return data[:-n]