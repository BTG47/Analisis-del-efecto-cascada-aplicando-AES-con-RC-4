# Decisiones de implementación — módulo AES (Bruno)

Documento breve para el informe y para José y Diego. Todo lo que está acá fue
decidido en conjunto; lo que no está, no está en el alcance.

## 1. Modo: AES-256-ECB sin IV

**Decisión:** ECB.

**Motivo:** el objeto de estudio es el cifrador, no el canal. ECB no introduce
IV ni encadenamiento, así que:

- el cifrado es determinista (`data` + `key` → siempre el mismo `bytes`);
- la comparación de dos criptogramas solo refleja el cambio en la clave;
- no hay bytes de IV contaminando el conteo de bits.

**Aclaración metodológica:** ECB **no es la única** forma de lograr
determinismo. CBC con IV fijo también lo es. Para *avalancha de clave* ambos
modos dan prácticamente el mismo resultado agregado, porque al cambiar la clave
cambian todos los bloques. ECB se elige por simplicidad y por no arrastrar IV al
cálculo.

**Límite:** ECB no es apto para producción. Filtra igualdad de bloques (mismo
bloque de texto plano → mismo bloque cifrado, en cualquier posición), es
determinista y no autentica.

## 2. PKCS#7

Se agrega **siempre** entre 1 y 16 bytes. Si la entrada ya es múltiplo de 16, se
agrega un bloque completo (`0x10` × 16). Motivo: al descifrar debe ser posible
distinguir "no había relleno" de "terminaba con un byte `0x01`".

`pkcs7_unpad` valida los `n` bytes de la cola y no solo el último. Relleno
inválido → `ValueError`.

## 3. Tamaños

Con `n = len(data)`:

| Elemento | Fórmula |
|---|---|
| `len(aes_encrypt(data))` | `16 * (n // 16 + 1)` |
| `len(aes_decrypt(ct))` | `n` |
| Overhead | siempre ≥ 1 byte; hasta 16 |

| `n` | 0 | 1 | 15 | 16 | 17 | 100 |
|---|---|---|---|---|---|---|
| cifrado | 16 | 16 | 16 | 32 | 32 | 112 |

Esto alimenta las tablas de tamaños del informe (antes / cifrado / descifrado).

## 4. Interfaz pública

```python
aes_encrypt(data: bytes, key: bytes) -> bytes
aes_decrypt(data: bytes, key: bytes) -> bytes
aes_encrypt_raw(data: bytes, key: bytes) -> bytes   # sin padding
aes_decrypt_raw(data: bytes, key: bytes) -> bytes   # sin padding
generate_key() -> bytes
```

- Solo `bytes` in / `bytes` out. Se aceptan `bytearray` y `memoryview` y se
  normalizan a `bytes`.
- Clave: exactamente 32 bytes (AES-256).
- `*_raw` existe **solo** para experimentos controlados: exige longitud
  múltiplo de 16 y no agrega relleno. Permite comparar AES contra RC4 con el
  mismo denominador de bits.

## 5. Contrato de errores

| Situación | Excepción |
|---|---|
| `data` o `key` de tipo incorrecto (`str`, `int`, …) | `TypeError` |
| Clave de largo distinto de 32 | `ValueError` |
| `*_raw` con `len % 16 != 0` | `ValueError` |
| Criptograma truncado / no múltiplo de 16 | `ValueError` |
| Relleno PKCS#7 inválido | `ValueError` |

No se definen excepciones propias: los compañeros solo necesitan `ValueError`.

## 6. Detección de clave incorrecta

`aes_decrypt` no autentica. Detecta la clave incorrecta **solo** porque el
relleno resultante suele ser inválido (~255 de cada 256 casos). Queda un caso
en el que devuelve basura silenciosamente. Para integridad real haría falta
HMAC o un modo AEAD; ambos fuera de alcance (la verificación de integridad es
responsabilidad de José).

## 7. Cascada AES-RC4 (diferida)

Cuando José entregue `rc4.py`, se agrega `hybrid.py` sin tocar `aes256.py`:

```python
def hybrid_encrypt(data, aes_key, rc4_key):
    return rc4_encrypt(aes_encrypt(data, aes_key), rc4_key)

def hybrid_decrypt(data, aes_key, rc4_key):
    return aes_decrypt(rc4_decrypt(data, rc4_key), aes_key)
```

- AES va primero; el padding viaja dentro del RC4.
- El criptograma híbrido mide lo mismo que el de AES (RC4 no cambia longitudes).
- Dos claves independientes; no hay master key ni derivación.
- Cambiar 1 bit de la clave AES ≠ cambiar 1 bit de la clave RC4 ≠ cambiar un bit
  en cada una. El protocolo de Diego debe distinguir los tres casos.

## 8. Vectores de validación

| Fuente | Qué valida |
|---|---|
| FIPS-197, Apéndice C.3 | AES-256, un bloque |
| NIST SP 800-38A, F.1.5 | ECB-AES256, cuatro bloques |

Verificados contra `cryptography 45.0.7` antes de escribir los tests.

## 9. Requisitos de entorno

- Python ≥ 3.9 (se usa `list[str]` y `bytes | None` en anotaciones; el código
  probado corre en 3.13).
- `cryptography` (única dependencia de runtime).
- `pytest` (solo desarrollo).

## 10. Supuestos

- Los archivos de práctica entran en memoria (sin streaming).
- El equipo usa el mismo intérprete con `cryptography` instalada.
