# Módulo AES — Tarea Information Security

Componente AES del trabajo práctico basado en *AES-RC4 Encryption Technique to
Improve File Security* (Atikah et al., 2019). Este repositorio contiene **solo
la parte de Bruno**: AES-256-ECB. RC4 y el análisis de Avalanche Effect viven en
los módulos de José y Diego.

## Estado

Esqueleto con tests escritos; implementación en curso. Ver `.partner/STATE.md`.

## Requisitos

| Requisito | Versión | Nota |
|---|---|---|
| Python | ≥ 3.9 (probado en 3.13) | sin entorno conda |
| `cryptography` | probado con 45.0.7 | única dependencia de runtime |
| `pytest` | probado con 9.2.0 | solo para correr los tests |

Instalación:

```bash
python -m pip install cryptography pytest
```

## Interfaz pública

```python
from aes256 import aes_encrypt, aes_decrypt, aes_encrypt_raw, aes_decrypt_raw, generate_key

ct = aes_encrypt(data, key)          # PKCS#7, cualquier longitud
pt = aes_decrypt(ct, key)            # ValueError si el relleno no es válido
ct = aes_encrypt_raw(data, key)      # sin padding, len(data) % 16 == 0
key = generate_key()                 # 32 bytes
```

`key` debe medir **32 bytes** (AES-256). Todo entra y sale como `bytes`.

## Estructura

```
aes256.py           # núcleo: AES-256-ECB, API pública
padding.py          # PKCS#7
validation.py       # tipos y largo de clave
scripts/file_cli.py # cifra/descifra archivos y reporta tamaños + SHA-256
tests/              # pytest
docs/DECISIONS.md   # decisiones y límites
```

## Tests

```bash
python -m pytest -q
```

## Uso con archivos (TODO: completar cuando esté implementado)

```bash
python scripts/file_cli.py generate-key
python scripts/file_cli.py encrypt entrada.bin salida.bin --key-hex <64 hex>
python scripts/file_cli.py decrypt salida.bin recuperado.bin --key-hex <64 hex>
```

## Advertencia

ECB se usa con fines **exclusivamente académicos**: es determinista y filtra
patrones de bloques repetidos. No usar para proteger datos reales. Ver
`docs/DECISIONS.md`.
