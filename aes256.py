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
    return os.urandom(KEY_SIZE)


def _encrypt_blocks(data: bytes, key: bytes) -> bytes:
    """Cifra ``data`` (múltiplo de BLOCK_SIZE) sin agregar padding."""

    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()
    cipher_text = encryptor.update(data) + encryptor.finalize()

    return cipher_text


def _decrypt_blocks(data: bytes, key: bytes) -> bytes:
    """Descifra ``data`` (múltiplo de BLOCK_SIZE) sin quitar padding."""
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()
    plain_text = decryptor.update(data) + decryptor.finalize()

    return plain_text


def aes_encrypt_raw(data: bytes, key: bytes) -> bytes:
    """Cifra sin padding. ``len(data)`` debe ser múltiplo de 16 (0 permitido)."""
    data = require_bytes(data)
    key = require_key(key)

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Error, data debe ser múltiplo de 16")

    encrypted_text = _encrypt_blocks(data, key)
    return encrypted_text


def aes_decrypt_raw(data: bytes, key: bytes) -> bytes:
    """Descifra sin padding. ``len(data)`` debe ser múltiplo de 16 (0 permitido)."""
    data = require_bytes(data)
    key = require_key(key)

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError("Error, data debe ser múltiplo de 16")

    plain_text = _decrypt_blocks(data, key)
    return plain_text


def aes_encrypt(data: bytes, key: bytes) -> bytes:
    """Cifra con PKCS#7. Acepta cualquier longitud, incluida 0."""
    data = require_bytes(data)
    key = require_key(key)

    # Aplicar padding
    data = pkcs7_pad(data)

    # Aplicar cifrado
    encrypted_data = _encrypt_blocks(data, key)
    return encrypted_data


def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """Descifra y valida PKCS#7.

    Lanza ``ValueError`` si el criptograma está truncado o si el relleno no es
    válido (clave incorrecta o datos corruptos). La detección es probabilística:
    con clave incorrecta el relleno inválido aparece en ~255 de cada 256 casos.
    """
    data = require_bytes(data)
    key = require_key(key)

    # Recuperar texto original
    padded_plain = _decrypt_blocks(data, key)

    # Se remueve el padding agregado
    plain_text = pkcs7_unpad(padded_plain)
    return plain_text