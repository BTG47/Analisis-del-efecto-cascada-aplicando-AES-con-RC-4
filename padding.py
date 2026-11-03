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


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Agrega relleno PKCS#7 a ``data``."""
    # TODO Misión 1
    # 1. require_bytes(data).
    # 2. Validar block_size: entero, 1 <= block_size <= MAX_BLOCK_SIZE.
    # 3. Cuántos bytes faltan? Ojo con el caso len(data) % block_size == 0.
    # 4. Devolver data + bytes([n]) * n.
    raise NotImplementedError("Misión 1: pkcs7_pad")


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Quita y valida el relleno PKCS#7 de ``data``."""
    # TODO Misión 1
    # 1. require_bytes(data).
    # 2. Rechazar data vacía y longitudes que no sean múltiplo de block_size.
    # 3. n = data[-1]; rechazar n == 0 o n > block_size.
    # 4. Rechazar si algún byte de data[-n:] != n.
    # 5. Devolver data[:-n].
    raise NotImplementedError("Misión 1: pkcs7_unpad")
