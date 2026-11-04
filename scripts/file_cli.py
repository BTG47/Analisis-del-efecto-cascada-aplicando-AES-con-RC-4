"""CLI de archivos: cifra y descifra con AES-256-ECB, RC4 o la cascada AES-RC4.

Esta es la capa SUPERIOR. No forma parte de la librería: acá viven las rutas de
archivo, la lectura/escritura y el reporte. La lógica criptográfica está en
``aes256.py``, ``rc4.py`` y ``hybrid.py``.

Uso:
    python scripts/file_cli.py generate-key
    python scripts/file_cli.py generate-rc4-key [--size 16]
    python scripts/file_cli.py encrypt  entrada.bin salida.bin   --key-hex <64 hex>
    python scripts/file_cli.py decrypt  salida.bin  vuelta.bin   --key-hex <64 hex>
    python scripts/file_cli.py rc4-encrypt entrada.bin salida.bin --key-hex <2..512 hex>
    python scripts/file_cli.py rc4-decrypt salida.bin  vuelta.bin --key-hex <2..512 hex>
    python scripts/file_cli.py hybrid-encrypt entrada.bin salida.bin \\
        --aes-key-hex <64 hex> --rc4-key-hex <2..512 hex>
    python scripts/file_cli.py hybrid-decrypt salida.bin  vuelta.bin \\
        --aes-key-hex <64 hex> --rc4-key-hex <2..512 hex>

Salida de todas las operaciones de archivo (una línea por dato, fácil de copiar
a una tabla del informe):

    archivo: <ruta>
    tamano_origen: <bytes>
    tamano_destino: <bytes>
    sha256_origen: <hex>
    sha256_destino: <hex>
"""

import argparse
import hashlib
import sys
from pathlib import Path

# Permite importar aes256 aunque el script se ejecute como scripts/file_cli.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aes256 import KEY_SIZE, aes_decrypt, aes_encrypt, generate_key  # noqa: E402
from hybrid import (  # noqa: E402
    RC4_KEY_MAX,
    RC4_KEY_MIN,
    generate_rc4_key,
    hybrid_decrypt,
    hybrid_encrypt,
)
from rc4 import rc4_decrypt, rc4_encrypt  # noqa: E402


def sha256(data: bytes) -> str:
    """Hash SHA-256 en hexadecimal (para verificar recuperación exacta)."""
    return hashlib.sha256(data).hexdigest()


def _report(src: Path, data: bytes, output: bytes) -> dict:
    """Arma el reporte común: archivo fuente, tamaños y hashes de entrada/salida."""
    return {
        "archivo": src,
        "tamano_origen": len(data),
        "tamano_destino": len(output),
        "sha256_origen": sha256(data),
        "sha256_destino": sha256(output),
    }


def encrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, cifra con AES-256-ECB + PKCS#7, escribe ``dst`` y reporta."""
    data = src.read_bytes()
    cifrado = aes_encrypt(data, key)
    dst.write_bytes(cifrado)
    return _report(src, data, cifrado)


def decrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, descifra AES y escribe ``dst``. Mismo reporte que encrypt_file."""
    data = src.read_bytes()
    plain_text = aes_decrypt(data, key)
    dst.write_bytes(plain_text)
    return _report(src, data, plain_text)


def rc4_encrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, cifra con RC4 y escribe ``dst`` (misma longitud)."""
    data = src.read_bytes()
    cifrado = rc4_encrypt(data, key)
    dst.write_bytes(cifrado)
    return _report(src, data, cifrado)


def rc4_decrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, descifra RC4 y escribe ``dst`` (misma longitud)."""
    data = src.read_bytes()
    plain_text = rc4_decrypt(data, key)
    dst.write_bytes(plain_text)
    return _report(src, data, plain_text)


def hybrid_encrypt_file(src: Path, dst: Path, aes_key: bytes, rc4_key: bytes) -> dict:
    """Lee ``src``, aplica la cascada AES-RC4 y escribe ``dst``."""
    data = src.read_bytes()
    cifrado = hybrid_encrypt(data, aes_key, rc4_key)
    dst.write_bytes(cifrado)
    return _report(src, data, cifrado)


def hybrid_decrypt_file(src: Path, dst: Path, aes_key: bytes, rc4_key: bytes) -> dict:
    """Lee ``src``, invierte la cascada AES-RC4 y escribe ``dst``."""
    data = src.read_bytes()
    plain_text = hybrid_decrypt(data, aes_key, rc4_key)
    dst.write_bytes(plain_text)
    return _report(src, data, plain_text)


def print_report(report: dict) -> None:
    """Imprime el reporte como ``clave: valor``, una línea por dato."""
    for key, value in report.items():
        print(f"{key}: {value}")


def parse_aes_key(key_hex: str) -> bytes:
    """Convierte hex a una clave AES de exactamente 32 bytes."""
    key = bytes.fromhex(key_hex)
    if len(key) != KEY_SIZE:
        raise ValueError(
            f"la clave AES debe medir {KEY_SIZE} bytes, se recibieron {len(key)}"
        )
    return key


def parse_rc4_key(key_hex: str) -> bytes:
    """Convierte hex a una clave RC4 de 1 a 256 bytes."""
    key = bytes.fromhex(key_hex)
    if not RC4_KEY_MIN <= len(key) <= RC4_KEY_MAX:
        raise ValueError(
            f"la clave RC4 debe medir entre {RC4_KEY_MIN} y {RC4_KEY_MAX} bytes, "
            f"se recibieron {len(key)}"
        )
    return key


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AES-256-ECB, RC4 y cascada AES-RC4 para archivos"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("generate-key", help="imprime una clave AES de 32 bytes en hex")

    p = sub.add_parser("generate-rc4-key", help="imprime una clave RC4 en hex")
    p.add_argument("--size", type=int, default=16, help="bytes (1 a 256), por defecto 16")

    for name in ("encrypt", "decrypt", "rc4-encrypt", "rc4-decrypt"):
        p = sub.add_parser(name)
        p.add_argument("src", type=Path)
        p.add_argument("dst", type=Path)
        p.add_argument("--key-hex", required=True, help="clave en hexadecimal")

    for name in ("hybrid-encrypt", "hybrid-decrypt"):
        p = sub.add_parser(name)
        p.add_argument("src", type=Path)
        p.add_argument("dst", type=Path)
        p.add_argument("--aes-key-hex", required=True, help="64 caracteres hexadecimales")
        p.add_argument("--rc4-key-hex", required=True, help="2 a 512 caracteres hexadecimales")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "generate-key":
        print(generate_key().hex())
        return 0

    if args.command == "generate-rc4-key":
        print(generate_rc4_key(args.size).hex())
        return 0

    if args.command == "encrypt":
        report = encrypt_file(args.src, args.dst, parse_aes_key(args.key_hex))
    elif args.command == "decrypt":
        report = decrypt_file(args.src, args.dst, parse_aes_key(args.key_hex))
    elif args.command == "rc4-encrypt":
        report = rc4_encrypt_file(args.src, args.dst, parse_rc4_key(args.key_hex))
    elif args.command == "rc4-decrypt":
        report = rc4_decrypt_file(args.src, args.dst, parse_rc4_key(args.key_hex))
    else:
        aes_key = parse_aes_key(args.aes_key_hex)
        rc4_key = parse_rc4_key(args.rc4_key_hex)
        if args.command == "hybrid-encrypt":
            report = hybrid_encrypt_file(args.src, args.dst, aes_key, rc4_key)
        else:
            report = hybrid_decrypt_file(args.src, args.dst, aes_key, rc4_key)

    print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
