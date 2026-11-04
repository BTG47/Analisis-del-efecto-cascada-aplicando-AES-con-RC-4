# Decisiones de implementación — AES-256 y cascada AES-RC4

Documento breve para el informe y el equipo. Todo lo que está acá fue
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
| `rc4_key` fuera de 1–256 bytes (cascada) | `ValueError` |
| `block_size` fuera de 1–255 en `pkcs7_pad` / `pkcs7_unpad` | `ValueError` |

No se definen excepciones propias: los compañeros solo necesitan `ValueError`.

## 6. Detección de clave incorrecta

`aes_decrypt` no autentica. Detecta la clave incorrecta **solo** porque el
relleno resultante suele ser inválido (~255 de cada 256 casos). Queda un caso
en el que devuelve basura silenciosamente. Para integridad real haría falta
HMAC o un modo AEAD; ambos fuera de alcance (la verificación de integridad es
responsabilidad del módulo de integridad).

En `hybrid_decrypt` ocurre lo mismo: una `rc4_key` incorrecta produce basura de
la longitud correcta y quien la descarta es la validación de PKCS#7 de AES. Por
eso el reporte de integridad (`integrity.py`) sigue siendo necesario: el
descifrado por sí solo no prueba que la clave fuera la correcta.

## 7. Cascada AES-RC4 (implementada)

`hybrid.py` compone los módulos existentes: no reimplementa nada y no modifica
`aes256.py` ni `rc4.py`.

```python
hybrid_encrypt(data, aes_key, rc4_key) -> bytes   # RC4( AES(data, aes_key), rc4_key)
hybrid_decrypt(data, aes_key, rc4_key) -> bytes   # AES⁻¹(RC4⁻¹(data, rc4_key), aes_key)
generate_rc4_key(size=16) -> bytes
```

- Orden AES → RC4 para cifrar, RC4 → AES para descifrar. Confirmado por el
  enunciado del trabajo (HW4, LIS4062).
- El padding PKCS#7 viaja **dentro** del RC4: lo agrega AES y lo valida AES al
  descifrar.
- El criptograma híbrido mide lo mismo que el de AES: `16 * (n // 16 + 1)`,
  porque RC4 no cambia longitudes.
- Dos claves independientes: AES 32 bytes exactos; RC4 1–256 bytes. Sin master
  key ni derivación.
- `hybrid.py` valida la clave RC4 en su frontera porque `rc4.py` acepta un `int`
  y lo convierte con `bytes(key)`; un `32` se volvería una clave de 32 ceros en
  silencio. El arreglo de fondo corresponde al módulo de RC4.

### Efecto avalancha de la cascada

Con una sola clave modificada, la cascada **hereda** el efecto avalancha del
cifrador cuya clave cambió; no lo amplifica:

| Bit invertido | Relación | Medición (2.000 bytes) |
|---|---|---|
| Clave AES, RC4 fija | `dH(híbrido) == dH(AES)`, exacta | 8.039 == 8.039 |
| Clave RC4, AES fija | aproximada, no exacta | 8.208 frente a 8.141 de RC4 |

La primera es exacta porque RC4 es `C = X ⊕ keystream` y el XOR con una
constante preserva la distancia de Hamming. La segunda no lo es porque la
cascada alimenta a RC4 con el criptograma de AES (16 bytes más largo), no con
el texto plano.

Consecuencia para la Tabla III del informe: si la fila "AES–RC4" se mide
invirtiendo la clave AES, la columna **duplica** la de AES. Para que aporte
información hay que invertir un bit de la clave RC4, y discutir que la cascada
no mejora la difusión: solo la conserva.

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

## 11. Evidencia de ejecución (2026-11-03)

Suite completa:

```
python -m pytest -q
186 passed in 1.08s
```

Distribución: 26 de padding, 5 de vectores AES, 24 de la API pública, 29 de la
ruta raw, 30 de la CLI, 17 de vectores RC4, 17 de integridad y 38 de la cascada
AES-RC4.

Prueba end-to-end con un archivo binario aleatorio de 1.000.000 bytes:

| Etapa | AES | RC4 | AES-RC4 |
|---|---|---|---|
| original | 1.000.000 | 1.000.000 | 1.000.000 |
| cifrado | 1.000.016 | 1.000.000 | 1.000.016 |
| descifrado | 1.000.000 | 1.000.000 | 1.000.000 |

Verificación de integridad: `sha256_destino` de la operación de cifrado coincide
con `sha256_origen` de la de descifrado, y viceversa. `check_integrity` sobre el
archivo recuperado devuelve `ber = 0.0`, `sha256_match = True` e
`identical = True`. La salida completa está en el README.

Compuerta de integración: `rc4.py` reproduce los tres vectores clásicos de RC4
(`Key`/`Plaintext`, `Wiki`/`pedia`, `Secret`/`Attack at dawn`) antes de
componerse en la cascada.

Verificación independiente de la suite (200 casos aleatorios, longitudes 0–1000,
claves nuevas): round-trip exacto, fórmula de tamaño correcta y
`aes_encrypt(x) == aes_encrypt_raw(pkcs7_pad(x))`. Una clave de 16 bytes se
rechaza con `ValueError` (sin esa validación, `cryptography` habría usado
AES-128 en silencio).
