from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

def cifrar_imagen_auto(imagen_bytes):
    clave = get_random_bytes(32)
    iv = get_random_bytes(16)

    padding_len = 16 - len(imagen_bytes) % 16
    imagen_bytes += bytes([padding_len]) * padding_len

    cipher = AES.new(clave, AES.MODE_CBC, iv)
    cifrado = cipher.encrypt(imagen_bytes)

    return {
        'imagen_cifrada': base64.b64encode(cifrado).decode('utf-8'),
        'clave': base64.b64encode(clave).decode('utf-8'),
        'iv': base64.b64encode(iv).decode('utf-8')
    }

# ✅ Pega aquí la función de descifrado automático
def descifrar_imagen_auto(cifrada_b64, clave_usuario, iv_b64):
    cifrado = base64.b64decode(cifrada_b64)
    clave = base64.b64decode(clave_usuario)
    iv = base64.b64decode(iv_b64)

    cipher = AES.new(clave, AES.MODE_CBC, iv)
    imagen_descifrada = cipher.decrypt(cifrado)

    padding_len = imagen_descifrada[-1]
    return imagen_descifrada[:-padding_len]
