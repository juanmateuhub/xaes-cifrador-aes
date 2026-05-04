xaes.py — Cifrador AES compatible con OpenSSL

Programa Python que cifra y descifra información mediante **AES-128 en modo CBC**, derivando la clave a partir de una contraseña con **PBKDF2** y empleando un *salt* aleatorio. Es **interoperable en ambas direcciones** con el comando estándar `openssl aes-128-cbc -pbkdf2`.

Proyecto desarrollado para la asignatura **EI1034 / MT1034 / EI1056 — Seguridad Informática** (Universitat Jaume I, curso 2025/2026).

## Requisitos

- Python 3.10 o superior.
- Librería [`cryptography`](https://cryptography.io/):
```bash
  pip install cryptography
```
- (Opcional) `openssl` para verificar la interoperabilidad.

## Uso

**Cifrar:**
```bash
cat fichero | ./xaes.py -e "micontraseña" > fichero.enc
```

**Descifrar:**
```bash
cat fichero.enc | ./xaes.py -d "micontraseña" > fichero.dec
```

En sistemas Unix puede ser necesario otorgar permisos de ejecución previamente:
```bash
chmod +x xaes.py
```

## Compatibilidad con OpenSSL

El programa es bidireccionalmente compatible con OpenSSL en su configuración `aes-128-cbc -pbkdf2`:

```bash
# Cifrar con OpenSSL, descifrar con xaes.py
cat fichero | openssl aes-128-cbc -pbkdf2 -k "clave" > fichero.enc
cat fichero.enc | ./xaes.py -d "clave" > fichero.dec

# Cifrar con xaes.py, descifrar con OpenSSL
cat fichero | ./xaes.py -e "clave" > fichero.enc
cat fichero.enc | openssl aes-128-cbc -pbkdf2 -d -k "clave" > fichero.dec
```

## Detalles técnicos

| Componente | Valor |
|---|---|
| Algoritmo | AES-128 |
| Modo | CBC |
| Padding | PKCS7 |
| Derivación de clave | PBKDF2-HMAC-SHA256 |
| Iteraciones | 10 000 |
| Longitud del salt | 8 bytes |
| Formato del fichero | `Salted__` (8 B) + salt (8 B) + ciphertext |

## Documentación

Una explicación detallada del diseño, la implementación y las pruebas realizadas se encuentra en el documento [`Memoria_Proyecto_A_xaes.docx`](Memoria_Proyecto_A_xaes.docx).
