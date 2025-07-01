from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import os
from dotenv import load_dotenv

load_dotenv()

# ✅ Decodificar correctamente la clave de 32 bytes desde Base64
master_key = base64.b64decode(os.getenv("MASTER_KEY_AES"))

def cifrar_clave(clave_base64):
    cipher = AES.new(master_key, AES.MODE_ECB)
    cifrada = cipher.encrypt(pad(base64.b64decode(clave_base64), AES.block_size))
    return base64.b64encode(cifrada).decode()

def descifrar_clave(clave_cifrada_base64):
    cipher = AES.new(master_key, AES.MODE_ECB)
    dec = cipher.decrypt(base64.b64decode(clave_cifrada_base64))
    return base64.b64encode(unpad(dec, AES.block_size)).decode()
