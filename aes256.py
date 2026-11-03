"""AES-256-ECB sobre ``bytes``.

Interfaz pública (contrato compartido con RC4 y Avalanche Effect):

    aes_encrypt(data, key)      -> bytes   # con PKCS#7, cualquier longitud
    aes_decrypt(data, key)      -> bytes   # valida y quita PKCS#7
    aes_encrypt_raw(data, key)  -> bytes   # sin padding, len múltiplo de 16
    aes_decrypt_raw(data, key)  -> bytes   # sin padding, len múltiplo de 16
    generate_key()              -> bytes   # 32 bytes aleatorios

Solo AES-256: la clave DEBE medir 32 bytes (``algorithms.AES`` deduce el
tamaño de clave del largo recibido; 32 bytes = 256 bits).

Modo ECB sin IV por decisión de laboratorio: ver docs/DECISIONS.md.
NO usar este módulo para proteger datos reales.
"""

import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from padding import pkcs7_pad, pkcs7_unpad
from validation import require_bytes, require_key

BLOCK_SIZE = 16
KEY_SIZE = 32


def generate_key() -> bytes:
    """Devuelve 32 bytes aleatorios de calidad criptográfica."""
    # TODO Misión 2: os.urandom(KEY_SIZE)
    raise NotImplementedError("Misión 2: generate_key")


def _encrypt_blocks(data: bytes, key: bytes) -> bytes:
    """Cifra ``data`` (múltiplo de BLOCK_SIZE) sin agregar padding."""
    # TODO Misión 2
    #
    # Cómo se usa cryptography (primera vez):
    #
    #   cipher    = Cipher(algorithms.AES(key), modes.ECB())   # 1. configurar
    #   encryptor = cipher.encryptor()                         # 2. contexto
    #   salida    = encryptor.update(data) + encryptor.finalize()  # 3. procesar
    #
    # Puntos importantes:
    # - El objeto Cipher es "de un solo uso": no lo reutilices entre llamadas.
    # - update() puede llamarse varias veces; acá alcanza con una.
    # - finalize() cierra el contexto y devuelve los bytes restantes.
    # - ECB exige que data sea múltiplo de 16; si no, lanza ValueError.
    raise NotImplementedError("Misión 2: _encrypt_blocks")


def _decrypt_blocks(data: bytes, key: bytes) -> bytes:
    """Descifra ``data`` (múltiplo de BLOCK_SIZE) sin quitar padding."""
    # TODO Misión 2: igual que _encrypt_blocks pero con cipher.decryptor().
    raise NotImplementedError("Misión 2: _decrypt_blocks")


def aes_encrypt_raw(data: bytes, key: bytes) -> bytes:
    """Cifra sin padding. ``len(data)`` debe ser múltiplo de 16 (0 permitido)."""
    # TODO Misión 3
    # - require_bytes(data) y require_key(key).
    # - Si len(data) % BLOCK_SIZE != 0 -> ValueError explicando el largo.
    # - Delegar en _encrypt_blocks.
    raise NotImplementedError("Misión 3: aes_encrypt_raw")


def aes_decrypt_raw(data: bytes, key: bytes) -> bytes:
    """Descifra sin padding. ``len(data)`` debe ser múltiplo de 16 (0 permitido)."""
    # TODO Misión 3: mismo contrato que aes_encrypt_raw.
    raise NotImplementedError("Misión 3: aes_decrypt_raw")


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """Cifra con PKCS#7. Acepta cualquier longitud, incluida 0."""
    # TODO Misión 3: require_key + require_bytes + pkcs7_pad + _encrypt_blocks.
    raise NotImplementedError("Misión 3: aes_encrypt")


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """Descifra y valida PKCS#7.

    Lanza ``ValueError`` si el criptograma está truncado o si el relleno no es
    válido (clave incorrecta o datos corruptos). La detección es probabilística:
    con clave incorrecta el relleno inválido aparece en ~255 de cada 256 casos.
    """
    # TODO Misión 3: _decrypt_blocks + pkcs7_unpad.
    raise NotImplementedError("Misión 3: aes_decrypt")
