"""Vectores oficiales de AES-256-ECB.

Fuentes:
- FIPS-197, Apéndice C.3 (AES-256, un bloque).
- NIST SP 800-38A, Apéndice F.1.5 (ECB-AES256, cuatro bloques).

Ambos fueron verificados contra ``cryptography 45.0.7`` antes de escribirlos.
Estos tests usan la ruta SIN padding: los vectores ya son múltiplos de 16.
"""

from aes256 import aes_decrypt_raw, aes_encrypt_raw

# --- FIPS-197 C.3 ---------------------------------------------------------

FIPS_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
    "101112131415161718191a1b1c1d1e1f"
)
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_CT = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")


def test_fips197_aes256_cifra():
    assert aes_encrypt_raw(FIPS_PT, FIPS_KEY) == FIPS_CT


def test_fips197_aes256_descifra():
    assert aes_decrypt_raw(FIPS_CT, FIPS_KEY) == FIPS_PT


# --- NIST SP 800-38A F.1.5 -----------------------------------------------

SP_KEY = bytes.fromhex(
    "603deb1015ca71be2b73aef0857d7781"
    "1f352c073b6108d72d9810a30914dff4"
)
SP_PT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
    "ae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52ef"
    "f69f2445df4f9b17ad2b417be66c3710"
)
SP_CT = bytes.fromhex(
    "f3eed1bdb5d2a03c064b5a7e3db181f8"
    "591ccb10d410ed26dc5ba74a31362870"
    "b6ed21b99ca6f4f9f153e7b1beafed1d"
    "23304b7a39f9f3ff067d8d8f9e24ecc7"
)


def test_sp800_38a_cifra_cuatro_bloques():
    assert aes_encrypt_raw(SP_PT, SP_KEY) == SP_CT


def test_sp800_38a_descifra_cuatro_bloques():
    assert aes_decrypt_raw(SP_CT, SP_KEY) == SP_PT


def test_cada_bloque_es_independiente():
    """ECB cifra cada bloque por separado: el vector completo es la concatenación."""
    esperado = b"".join(
        aes_encrypt_raw(SP_PT[i : i + 16], SP_KEY) for i in range(0, len(SP_PT), 16)
    )
    assert esperado == SP_CT
