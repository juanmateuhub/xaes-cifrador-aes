#!/usr/bin/env python3
# xaes.py - Cifrador/descifrador AES-128-CBC compatible con OpenSSL
# Proyecto A - Seguridad Informatica - Curso 2025/2026

import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding


# Cabecera que pone OpenSSL al principio del fichero cifrado
MAGIC = b"Salted__"


def derive_key_iv(password, salt):
    # Derivamos 32 bytes con PBKDF2-HMAC-SHA256 y 10000 iteraciones
    # (parametros que usa internamente "openssl aes-128-cbc -pbkdf2").
    # Los primeros 16 bytes son la clave AES y los siguientes 16 el IV.
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=10000,
    )
    key_iv = kdf.derive(password.encode("utf-8"))
    key = key_iv[:16]
    iv = key_iv[16:]
    return key, iv


def encrypt(plaintext, password):
    # 1. Generamos un salt aleatorio de 8 bytes
    salt = os.urandom(8)

    # 2. Derivamos clave e IV a partir de la contrasena y el salt
    key, iv = derive_key_iv(password, salt)

    # 3. Aplicamos padding PKCS7 para que el plaintext sea multiplo de 16 bytes
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # 4. Ciframos con AES-128-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # 5. Devolvemos el resultado en formato OpenSSL: "Salted__" + salt + ciphertext
    return MAGIC + salt + ciphertext


def decrypt(blob, password):
    # 1. Comprobamos que el fichero empieza con la cabecera "Salted__"
    if blob[:8] != MAGIC:
        raise ValueError("El fichero no tiene formato OpenSSL.")

    # 2. Extraemos el salt (8 bytes despues de la cabecera) y el ciphertext (el resto)
    salt = blob[8:16]
    ciphertext = blob[16:]

    # 3. Derivamos la misma clave e IV con la contrasena y el salt extraido
    key, iv = derive_key_iv(password, salt)

    # 4. Desciframos con AES-128-CBC
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # 5. Quitamos el padding PKCS7 para recuperar el plaintext original
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext


def main():
    # Comprobamos que recibimos exactamente -e/-d y la contrasena
    if len(sys.argv) != 3 or sys.argv[1] not in ("-e", "-d"):
        sys.stderr.write("Uso: xaes.py -e|-d <contrasena>\n")
        sys.exit(1)

    modo = sys.argv[1]
    password = sys.argv[2]

    # Leemos los datos de la entrada estandar como bytes binarios
    data = sys.stdin.buffer.read()

    try:
        if modo == "-e":
            resultado = encrypt(data, password)
        else:
            resultado = decrypt(data, password)
    except Exception as e:
        sys.stderr.write("Error: " + str(e) + "\n")
        sys.stderr.write("Causa probable: contrasena incorrecta o fichero no valido.\n")
        sys.exit(1)

    # Escribimos el resultado en la salida estandar como bytes binarios
    sys.stdout.buffer.write(resultado)


if __name__ == "__main__":
    main()