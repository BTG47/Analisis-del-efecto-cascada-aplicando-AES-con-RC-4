"""Tests de la capa de archivos (CLI).

Fijan el contrato del reporte: tamaños y hashes de entrada y salida.
"""

import hashlib

import pytest

from scripts.file_cli import (
    decrypt_file,
    encrypt_file,
    hybrid_decrypt_file,
    hybrid_encrypt_file,
    main,
    rc4_encrypt_file,
    sha256,
)

KEY = bytes(range(32))
KEY_HEX = KEY.hex()
RC4_KEY = b"rc4-secreto-16b"
RC4_KEY_HEX = RC4_KEY.hex()


def padded_len(n: int) -> int:
    return 16 * (n // 16 + 1)


def test_sha256_helper():
    assert sha256(b"") == hashlib.sha256(b"").hexdigest()
    assert sha256(b"abc") == hashlib.sha256(b"abc").hexdigest()


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_encrypt_file_reporta_tamanos_y_hashes(tmp_path, n):
    src = tmp_path / "orig.bin"
    dst = tmp_path / "orig.enc"
    data = bytes((i * 7) % 256 for i in range(n))
    src.write_bytes(data)

    report = encrypt_file(src, dst, KEY)
    cifrado = dst.read_bytes()

    assert report["tamano_origen"] == n
    assert report["tamano_destino"] == padded_len(n)
    assert report["sha256_origen"] == hashlib.sha256(data).hexdigest()
    assert report["sha256_destino"] == hashlib.sha256(cifrado).hexdigest()
    assert len(cifrado) == padded_len(n)


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_decrypt_file_recupera_exacto(tmp_path, n):
    src = tmp_path / "orig.bin"
    enc = tmp_path / "orig.enc"
    dec = tmp_path / "orig.dec"
    data = bytes((i * 11) % 256 for i in range(n))
    src.write_bytes(data)

    encrypt_file(src, enc, KEY)
    report = decrypt_file(enc, dec, KEY)

    assert dec.read_bytes() == data
    assert report["tamano_origen"] == padded_len(n)
    assert report["tamano_destino"] == n
    assert report["sha256_destino"] == hashlib.sha256(data).hexdigest()


def test_main_encrypt_y_decrypt(tmp_path, capsys):
    src = tmp_path / "a.bin"
    enc = tmp_path / "a.enc"
    dec = tmp_path / "a.dec"
    src.write_bytes(b"hola mundo")

    assert main(["encrypt", str(src), str(enc), "--key-hex", KEY_HEX]) == 0
    assert main(["decrypt", str(enc), str(dec), "--key-hex", KEY_HEX]) == 0
    assert dec.read_bytes() == b"hola mundo"

    salida = capsys.readouterr().out
    assert "tamano_origen" in salida
    assert "tamano_destino" in salida
    assert "sha256_origen" in salida
    assert "sha256_destino" in salida


def test_main_rechaza_clave_corta(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    with pytest.raises(ValueError):
        main(["encrypt", str(src), str(tmp_path / "a.enc"), "--key-hex", "00" * 16])


# --- RC4 y cascada AES-RC4 --------------------------------------------------


@pytest.mark.parametrize("n", [0, 1, 16, 17, 1000])
def test_rc4_file_preserva_longitud(tmp_path, n):
    src = tmp_path / "orig.bin"
    dst = tmp_path / "orig.rc4"
    data = bytes((i * 5) % 256 for i in range(n))
    src.write_bytes(data)

    report = rc4_encrypt_file(src, dst, RC4_KEY)

    assert report["tamano_origen"] == n
    assert report["tamano_destino"] == n
    assert len(dst.read_bytes()) == n
    assert report["sha256_origen"] == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("n", [0, 1, 15, 16, 17, 1000])
def test_hybrid_file_recupera_exacto(tmp_path, n):
    src = tmp_path / "orig.bin"
    enc = tmp_path / "orig.enc"
    dec = tmp_path / "orig.dec"
    data = bytes((i * 3) % 256 for i in range(n))
    src.write_bytes(data)

    report = hybrid_encrypt_file(src, enc, KEY, RC4_KEY)
    assert report["tamano_origen"] == n
    assert report["tamano_destino"] == padded_len(n)

    report = hybrid_decrypt_file(enc, dec, KEY, RC4_KEY)
    assert dec.read_bytes() == data
    assert report["tamano_origen"] == padded_len(n)
    assert report["tamano_destino"] == n
    assert report["sha256_destino"] == hashlib.sha256(data).hexdigest()


def test_main_hybrid_encrypt_y_decrypt(tmp_path, capsys):
    src = tmp_path / "a.bin"
    enc = tmp_path / "a.enc"
    dec = tmp_path / "a.dec"
    src.write_bytes(b"cascada aes-rc4")

    assert (
        main(
            [
                "hybrid-encrypt",
                str(src),
                str(enc),
                "--aes-key-hex",
                KEY_HEX,
                "--rc4-key-hex",
                RC4_KEY_HEX,
            ]
        )
        == 0
    )
    assert enc.stat().st_size == padded_len(len(b"cascada aes-rc4"))

    assert (
        main(
            [
                "hybrid-decrypt",
                str(enc),
                str(dec),
                "--aes-key-hex",
                KEY_HEX,
                "--rc4-key-hex",
                RC4_KEY_HEX,
            ]
        )
        == 0
    )
    assert dec.read_bytes() == b"cascada aes-rc4"

    salida = capsys.readouterr().out
    for campo in ("archivo", "tamano_origen", "tamano_destino", "sha256_origen", "sha256_destino"):
        assert f"{campo}:" in salida


def test_main_rc4_encrypt_y_decrypt(tmp_path):
    src = tmp_path / "a.bin"
    enc = tmp_path / "a.rc4"
    dec = tmp_path / "a.dec"
    src.write_bytes(b"rc4 simetrico")

    assert main(["rc4-encrypt", str(src), str(enc), "--key-hex", RC4_KEY_HEX]) == 0
    assert main(["rc4-decrypt", str(enc), str(dec), "--key-hex", RC4_KEY_HEX]) == 0
    assert dec.read_bytes() == b"rc4 simetrico"


def test_main_hybrid_rechaza_clave_rc4_vacia(tmp_path):
    src = tmp_path / "a.bin"
    src.write_bytes(b"x")
    with pytest.raises(ValueError):
        main(
            [
                "hybrid-encrypt",
                str(src),
                str(tmp_path / "a.enc"),
                "--aes-key-hex",
                KEY_HEX,
                "--rc4-key-hex",
                "",
            ]
        )


def test_main_genera_claves(capsys):
    assert main(["generate-key"]) == 0
    assert main(["generate-rc4-key"]) == 0
    assert main(["generate-rc4-key", "--size", "32"]) == 0

    lineas = capsys.readouterr().out.split()
    assert [len(bytes.fromhex(linea)) for linea in lineas] == [32, 16, 32]
