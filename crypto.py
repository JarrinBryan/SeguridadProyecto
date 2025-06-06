from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

def cifrar_imagen(imagen_bytes, llave):
    salt = os.urandom(16)
    clave = PBKDF2(llave, salt, dkLen=32)
    iv = os.urandom(16)
    cipher = AES.new(clave, AES.MODE_CBC, iv)

    # Padding
    padding_len = 16 - len(imagen_bytes) % 16
    imagen_bytes += bytes([padding_len]) * padding_len

    cifrado = cipher.encrypt(imagen_bytes)
    return base64.b64encode(salt + iv + cifrado).decode('utf-8')

def descifrar_imagen(cifrada_b64, llave):
    datos = base64.b64decode(cifrada_b64)
    salt = datos[:16]
    iv = datos[16:32]
    cifrado = datos[32:]

    clave = PBKDF2(llave, salt, dkLen=32)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    imagen_descifrada = cipher.decrypt(cifrado)

    # Eliminar padding
    padding_len = imagen_descifrada[-1]
    return imagen_descifrada[:-padding_len]
