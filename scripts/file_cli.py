"""CLI de archivos: cifra y descifra un archivo con AES-256-ECB.

Esta es la capa SUPERIOR. No forma parte de la librería y no se importa desde
``aes256``: acá viven las rutas de archivo, la lectura/escritura y el reporte.

Uso:
    python scripts/file_cli.py generate-key
    python scripts/file_cli.py encrypt entrada.bin salida.bin --key-hex <64 hex>
    python scripts/file_cli.py decrypt salida.bin recuperado.bin --key-hex <64 hex>

Salida esperada de encrypt/decrypt (una línea por dato, fácil de copiar a una tabla):

    archivo          <ruta>
    tamano_origen    <bytes>
    tamano_destino   <bytes>
    sha256_origen    <hex>
    sha256_destino   <hex>
"""

import argparse
import hashlib
import sys
from pathlib import Path

# Permite importar aes256 aunque el script se ejecute como scripts/file_cli.py
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from aes256 import aes_decrypt, aes_encrypt, generate_key  # noqa: E402


def sha256(data: bytes) -> str:
    """Hash SHA-256 en hexadecimal (para verificar recuperación exacta)."""
    return hashlib.sha256(data).hexdigest()


def encrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, cifra con PKCS#7, escribe ``dst`` y devuelve los datos del reporte."""
    # TODO Misión 4
    # - data = src.read_bytes()
    # - cifrado = aes_encrypt(data, key)
    # - dst.write_bytes(cifrado)
    # - Devolver un dict con: archivo, tamano_origen, tamano_destino,
    #   sha256_origen, sha256_destino.
    raise NotImplementedError("Misión 4: encrypt_file")


def decrypt_file(src: Path, dst: Path, key: bytes) -> dict:
    """Lee ``src``, descifra y escribe ``dst``. Mismo reporte que encrypt_file."""
    # TODO Misión 4
    raise NotImplementedError("Misión 4: decrypt_file")


def print_report(report: dict) -> None:
    """Imprime el reporte en formato clave<TAB>valor."""
    # TODO Misión 4: recorrer el dict e imprimir con formato alineado.
    raise NotImplementedError("Misión 4: print_report")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="AES-256-ECB para archivos")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("generate-key", help="imprime una clave de 32 bytes en hex")

    for name in ("encrypt", "decrypt"):
        p = sub.add_parser(name)
        p.add_argument("src", type=Path)
        p.add_argument("dst", type=Path)
        p.add_argument("--key-hex", required=True, help="64 caracteres hexadecimales")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "generate-key":
        print(generate_key().hex())
        return 0

    # TODO Misión 4
    # - bytes.fromhex(args.key_hex) y validar que mida 32 bytes.
    # - Llamar a encrypt_file o decrypt_file según args.command.
    # - Imprimir el reporte y devolver 0.
    raise NotImplementedError("Misión 4: main")


if __name__ == "__main__":
    raise SystemExit(main())
