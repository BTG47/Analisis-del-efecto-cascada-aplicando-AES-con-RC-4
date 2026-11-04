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

    if not isinstance(block_size, int):
        raise TypeError("Block size debe ser tipo int")
    data = require_bytes(data, "bloque")

    isTheSizePermitted = 1 <= block_size and block_size <= MAX_BLOCK_SIZE 
    if not isTheSizePermitted:
        raise ValueError(f"El tamaño no se encuentra entre 1 a {MAX_BLOCK_SIZE}")

    # obtener los bytes faltantes
    n = block_size - (len(data)%block_size)
    padding = bytes([n]) * n

    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Quita y valida el relleno PKCS#7 de ``data``."""
    # TODO Misión 1
    # 1. require_bytes(data).
    # 2. Rechazar data vacía y longitudes que no sean múltiplo de block_size.
    # 3. n = data[-1]; rechazar n == 0 o n > block_size.
    # 4. Rechazar si algún byte de data[-n:] != n.
    # 5. Devolver data[:-n].

    data = require_bytes(data)

    if not data or len(data) % block_size != 0:
        raise ValueError(f"El tamaño de data ({len(data)}) debe ser múltiplo de block size ({block_size})")

    n = data[-1]
    if n == 0 or n > block_size:
        raise ValueError("N no se encuentra dentro del rango esperado (1 <= data <= block_size)")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("Error, los datos de n no coinciden con los esperados")

    return data[:-n]