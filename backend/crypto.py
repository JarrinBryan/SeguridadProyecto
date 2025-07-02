from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64
import os

# =============================
# CIFRADO AUTOMÁTICO DE IMAGEN
# =============================
def cifrar_imagen_auto(imagen_bytes):
    # 1. Generar sal aleatoria
    salt = os.urandom(16)

    # 2. Derivar clave AES-256 desde clave base aleatoria + salt
    clave_base = get_random_bytes(16)  # clave temporal base
    clave = PBKDF2(clave_base, salt, dkLen=32, count=100_000)

    # 3. Generar IV aleatorio
    iv = get_random_bytes(16)

    # 4. Aplicar padding (PKCS7)
    padding_len = 16 - len(imagen_bytes) % 16
    imagen_bytes += bytes([padding_len]) * padding_len

    # 5. Cifrar con AES CBC
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    cifrado = cipher.encrypt(imagen_bytes)

    # 6. Devolver datos codificados
    return {
        'imagen_cifrada': base64.b64encode(cifrado).decode('utf-8'),
        'clave': base64.b64encode(clave_base).decode('utf-8'),  # Solo la clave base
        'iv': base64.b64encode(iv).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8')  # Salt para derivación
    }

# =============================
# DESCIFRADO AUTOMÁTICO DE IMAGEN
# =============================
def descifrar_imagen_auto(cifrada_b64, clave_base_b64, iv_b64, salt_b64):
    # 1. Decodificar todo de base64
    cifrado = base64.b64decode(cifrada_b64)
    clave_base = base64.b64decode(clave_base_b64)
    iv = base64.b64decode(iv_b64)
    salt = base64.b64decode(salt_b64)

    # 2. Derivar la misma clave AES con PBKDF2
    clave = PBKDF2(clave_base, salt, dkLen=32, count=100_000)

    # 3. Descifrar
    cipher = AES.new(clave, AES.MODE_CBC, iv)
    imagen_descifrada = cipher.decrypt(cifrado)

    # 4. Eliminar padding
    padding_len = imagen_descifrada[-1]
    return imagen_descifrada[:-padding_len]
