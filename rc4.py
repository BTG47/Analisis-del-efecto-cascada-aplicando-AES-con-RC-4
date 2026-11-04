"""RC4 stream cipher (KSA + PRGA + XOR), implemented from scratch.

Homework 4, LIS4062 (Autumn 2026) -- module owned by Jose Manuel Daniel Morales.
Standard library only. Follows the team's shared interface:

    rc4_encrypt(data: bytes, key: bytes) -> bytes
    rc4_decrypt(data: bytes, key: bytes) -> bytes

RC4 is symmetric: decryption is the same XOR with the same keystream, so the
ciphertext has exactly the same length as the plaintext (no padding, no IV,
no header).
"""

__all__ = ["ksa", "prga", "keystream", "rc4_encrypt", "rc4_decrypt"]


def _check_key(key: bytes) -> bytes:
    if isinstance(key, str):
        key = key.encode("utf-8")
    key = bytes(key)
    if not 1 <= len(key) <= 256:
        raise ValueError("RC4 key must be 1 to 256 bytes long")
    return key


def ksa(key: bytes) -> list:
    """Key-Scheduling Algorithm: returns the initial permutation S of 0..255."""
    key = _check_key(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    return s


def prga(s: list, n: int) -> bytes:
    """Pseudo-Random Generation Algorithm: n keystream bytes from state S.

    S is modified in place, as in the specification.
    """
    out = bytearray(n)
    i = j = 0
    for k in range(n):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[k] = s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def keystream(key: bytes, n: int) -> bytes:
    """First n bytes of the RC4 keystream for key (no bytes discarded)."""
    return prga(ksa(key), n)


def rc4_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypt data with RC4: C = P XOR keystream(K)."""
    data = bytes(data)
    ks = keystream(key, len(data))
    # XOR whole buffers through big integers: much faster than a byte loop
    # in pure Python and gives the same result.
    x = int.from_bytes(data, "big") ^ int.from_bytes(ks, "big")
    return x.to_bytes(len(data), "big")


def rc4_decrypt(data: bytes, key: bytes) -> bytes:
    """Decrypt RC4 ciphertext. Identical to encryption: P = C XOR keystream(K)."""
    return rc4_encrypt(data, key)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 5 or sys.argv[1] not in ("enc", "dec"):
        print("usage: python3 rc4.py enc|dec <key> <input_file> <output_file>")
        sys.exit(1)
    mode, key, src, dst = sys.argv[1:]
    with open(src, "rb") as f:
        data = f.read()
    fn = rc4_encrypt if mode == "enc" else rc4_decrypt
    with open(dst, "wb") as f:
        f.write(fn(data, key.encode("utf-8")))
    print(f"{mode}: {src} ({len(data)} bytes) -> {dst}")
