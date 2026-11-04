"""Tests de la capa de archivos (CLI).

Fijan el contrato del reporte: tamaños y hashes de entrada y salida.
"""

import hashlib

import pytest

from scripts.file_cli import decrypt_file, encrypt_file, main, sha256

KEY = bytes(range(32))
KEY_HEX = KEY.hex()


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
