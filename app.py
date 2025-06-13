from flask import Flask, request, render_template, jsonify, redirect, url_for
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient
from crypto import cifrar_imagen, descifrar_imagen
import os
import certifi
import base64
from flask import send_file
from io import BytesIO
from datetime import datetime, timedelta
import jwt
from bson import ObjectId
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

# Cargar variables de entorno
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
SECRET_KEY = "super_clave_segura_2025"

# Conexión a MongoDB
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['ProyectoS']
coleccion = db['imagenes']

app = Flask(__name__)
CORS(app)

# Ruta principal (login)
@app.route('/')
def index():
    return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)

# Página principal tras el login
@app.route('/inicio')
def inicio():
    return render_template('index.html')

# Cifrar imagen
@app.route('/cifrar', methods=['POST'])
def cifrar():
    try:
        imagen = request.files['imagen']
        llave = request.form['llave']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']

        imagen_bytes = imagen.read()
        cifrada = cifrar_imagen(imagen_bytes, llave)

        coleccion.insert_one({
            'usuario': usuario,
            'nombre_imagen': nombre_imagen,
            'imagen_cifrada': cifrada,
            'fecha': datetime.now()
        })

        return jsonify({'mensaje': '✅ Imagen cifrada y guardada correctamente.'})
    except Exception as e:
        print("Error en /cifrar:", e)
        return jsonify({'error': '❌ Error al cifrar o guardar la imagen.'}), 500

# Ver historial
@app.route('/historial')
def historial():
    documentos = list(coleccion.find({}, {'_id': 0}))
    return render_template('historial.html', documentos=documentos)

# Página para descifrar
@app.route('/descifrar', methods=['GET', 'POST'])
def descifrar():
    if request.method == 'GET':
        return render_template('descifrar.html')

    try:
        token = request.form['token']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']
        llave = request.form['llave']

        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if datos['usuario'] != usuario:
            return jsonify({'error': 'El token no pertenece a ese usuario.'}), 403

        doc = coleccion.find_one({
            'usuario': usuario,
            'nombre_imagen': nombre_imagen
        })

        if not doc:
            return jsonify({'error': 'Imagen no encontrada para ese usuario.'}), 404

        cifrada = doc['imagen_cifrada']
        imagen_bytes = descifrar_imagen(cifrada, llave)

        imagen_base64 = base64.b64encode(imagen_bytes).decode('utf-8')
        return jsonify({'imagen': imagen_base64})

    except jwt.ExpiredSignatureError:
        return jsonify({'error': '❌ El token ha expirado. Inicia sesión nuevamente.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': '❌ Token inválido. Verifica tu autenticación.'}), 401
    except Exception as e:
        print("Error al descifrar:", e)
        return jsonify({'error': '❌ No se pudo descifrar. ¿La llave es correcta?'}), 400

# Google login callback (POST)


@app.route('/google-login', methods=['POST'])
def google_login():
    try:
        data = request.get_json()
        token_google = data.get('credential')

        print("TOKEN recibido:", token_google)  # <-- Esta línea debe estar aquí, DENTRO del try

        if not token_google:
            return jsonify({"error": "❌ Token de Google no proporcionado."}), 400

        idinfo = id_token.verify_oauth2_token(
            token_google,
            grequests.Request(),
            audience=GOOGLE_CLIENT_ID
        )

        email = idinfo['email']
        nombre = idinfo.get('name', email)

        usuarios_col = db['usuarios']
        usuario_db = usuarios_col.find_one({'email': email})
        if not usuario_db:
            usuarios_col.insert_one({
                "email": email,
                "nombre": nombre,
                "rol": "usuario",
                "claveAES": None
            })

        token = jwt.encode({
            "usuario": email,
            "exp": datetime.utcnow() + timedelta(hours=2)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({"token": token, "usuario": email, "nombre": nombre})

    except ValueError as ve:
        print("Token de Google inválido:", ve)
        return jsonify({"error": "❌ Token inválido o manipulado."}), 400
    except Exception as e:
        print("Error inesperado:", e)
        return jsonify({"error": "❌ Error interno verificando token."}), 500
    
    


# Ejecutar en localhost
if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
