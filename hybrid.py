"""Cascada AES-RC4 sobre ``bytes``.

Composición de los módulos del equipo, sin duplicar algoritmos:

    cifrado:    data --AES-256-ECB (PKCS#7)--> C1 --RC4--> C2
    descifrado: C2   --RC4--> C1 --AES-256-ECB (unpad)--> data

Orden fijado por el enunciado del trabajo (HW4, LIS4062): AES primero, RC4
después. El padding viaja dentro del RC4 porque AES lo necesita y RC4 no.

Este módulo solo compone: no reimplementa nada ni modifica ``aes256`` ni
``rc4``. No usar ECB para proteger datos reales (ver ``docs/DECISIONS.md``).
"""

import os

from aes256 import KEY_SIZE, aes_decrypt, aes_encrypt
from rc4 import rc4_decrypt, rc4_encrypt
from validation import require_bytes, require_key

BLOCK_SIZE = 16
RC4_KEY_MIN = 1
RC4_KEY_MAX = 256
RC4_KEY_DEFAULT = 16


def generate_rc4_key(size: int = RC4_KEY_DEFAULT) -> bytes:
    """Devuelve ``size`` bytes aleatorios para usar como clave RC4 (1 a 256)."""
    if not RC4_KEY_MIN <= size <= RC4_KEY_MAX:
        raise ValueError(f"size debe estar entre {RC4_KEY_MIN} y {RC4_KEY_MAX}, se recibió {size}")
    return os.urandom(size)


def _require_rc4_key(key: object) -> bytes:
    """Valida una clave RC4: bytes-like de 1 a 256 bytes.

    No usa ``require_key``: AES exige exactamente 32 bytes, RC4 acepta 1..256.
    Tampoco se delega la validación al módulo de RC4, que hoy acepta ``int``
    (``bytes(32)`` sería una clave de 32 ceros en silencio).
    """
    key = require_bytes(key, "rc4_key")
    if not RC4_KEY_MIN <= len(key) <= RC4_KEY_MAX:
        raise ValueError(
            f"rc4_key debe medir entre {RC4_KEY_MIN} y {RC4_KEY_MAX} bytes, "
            f"se recibieron {len(key)}"
        )
    return key


def hybrid_encrypt(data: bytes, aes_key: bytes, rc4_key: bytes) -> bytes:
    """Cifra con AES-256-ECB (PKCS#7) y luego aplica RC4 al resultado."""
    data = require_bytes(data)
    aes_key = require_key(aes_key, KEY_SIZE)
    rc4_key = _require_rc4_key(rc4_key)
    return rc4_encrypt(aes_encrypt(data, aes_key), rc4_key)


def hybrid_decrypt(data: bytes, aes_key: bytes, rc4_key: bytes) -> bytes:
    """Invierte la cascada: RC4 y después AES, que valida y quita el PKCS#7."""
    data = require_bytes(data)
    aes_key = require_key(aes_key, KEY_SIZE)
    rc4_key = _require_rc4_key(rc4_key)

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            f"el criptograma debe ser múltiplo de {BLOCK_SIZE}, se recibieron {len(data)}"
        )

    return aes_decrypt(rc4_decrypt(data, rc4_key), aes_key)
