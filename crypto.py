from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
import os
import hmac
import hashlib

def cifrar_imagen(imagen_bytes, llave):
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    # Derivar clave de cifrado desde la llave usando PBKDF2
    clave = PBKDF2(llave, salt, dkLen=32)

    cipher = AES.new(clave, AES.MODE_CBC, iv)

    # Padding
    padding_len = 16 - len(imagen_bytes) % 16
    imagen_bytes += bytes([padding_len]) * padding_len

    cifrado = cipher.encrypt(imagen_bytes)

    # Crear HMAC (firma de integridad): HMAC(salt + iv + cifrado)
    hmac_key = hashlib.sha256(llave.encode()).digest()
    hmac_sha = hmac.new(hmac_key, salt + iv + cifrado, hashlib.sha256).digest()

    # Retornar todo codificado: salt + iv + cifrado + hmac
    return base64.b64encode(salt + iv + cifrado + hmac_sha).decode('utf-8')


def descifrar_imagen(cifrada_b64, llave):
    datos = base64.b64decode(cifrada_b64)

    salt = datos[:16]
    iv = datos[16:32]
    hmac_recibido = datos[-32:]
    cifrado = datos[32:-32]

    # Recalcular HMAC y verificar integridad
    hmac_key = hashlib.sha256(llave.encode()).digest()
    hmac_local = hmac.new(hmac_key, salt + iv + cifrado, hashlib.sha256).digest()

    if not hmac.compare_digest(hmac_local, hmac_recibido):
        raise ValueError("❌ Integridad comprometida. HMAC no coincide.")

    clave = PBKDF2(llave, salt, dkLen=32)
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    imagen_descifrada = cipher.decrypt(cifrado)

    # Eliminar padding
    padding_len = imagen_descifrada[-1]
    return imagen_descifrada[:-padding_len]
