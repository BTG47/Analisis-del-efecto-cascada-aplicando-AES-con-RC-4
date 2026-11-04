"""Integrity checks after decryption: binary comparison, SHA-256 and BER.

Homework 4, LIS4062 (Autumn 2026) -- module owned by Jose Manuel Daniel Morales.
Standard library only.

BER follows Eq. (2) of Atikah et al. (2019):

    BER(P, P') = (number of bits that differ between P and P') / (total bits of P)

The paper requires P and P' to have the same number of bits. If they do not,
this module still returns a value: every bit that is missing or extra counts
as an error, so a truncated or padded file never gets BER = 0.
"""

import hashlib

__all__ = ["bit_errors", "ber", "sha256_hex", "identical", "check_integrity"]


def bit_errors(a: bytes, b: bytes) -> int:
    """Number of differing bits; length mismatch counts as errors."""
    n = min(len(a), len(b))
    diff = 0
    if n:
        x = int.from_bytes(a[:n], "big") ^ int.from_bytes(b[:n], "big")
        diff = bin(x).count("1")
    return diff + 8 * abs(len(a) - len(b))


def ber(original: bytes, decrypted: bytes) -> float:
    """Bit error ratio between the original file and the decrypted file."""
    total = 8 * max(len(original), len(decrypted))
    if total == 0:
        return 0.0
    return bit_errors(original, decrypted) / total


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def identical(a: bytes, b: bytes) -> bool:
    """Byte-for-byte comparison."""
    return a == b


def check_integrity(original: bytes, decrypted: bytes) -> dict:
    """All checks in one record, ready to be written to a results table."""
    h1, h2 = sha256_hex(original), sha256_hex(decrypted)
    return {
        "original_size": len(original),
        "decrypted_size": len(decrypted),
        "identical": identical(original, decrypted),
        "sha256_original": h1,
        "sha256_decrypted": h2,
        "sha256_match": h1 == h2,
        "bit_errors": bit_errors(original, decrypted),
        "ber": ber(original, decrypted),
    }
