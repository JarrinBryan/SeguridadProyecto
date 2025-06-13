import os
import base64
import certifi
import jwt
import requests
from io import BytesIO
from datetime import datetime, timedelta
from flask import Flask, request, render_template, jsonify, redirect, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient
from urllib.parse import urlencode
from bson import ObjectId
from crypto import cifrar_imagen, descifrar_imagen

# === Cargar variables de entorno ===
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
SECRET_KEY = "super_clave_segura_2025"

# === Conectar a MongoDB Atlas de forma segura ===
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['ProyectoS']
coleccion = db['imagenes']

# === Iniciar aplicación Flask ===
app = Flask(__name__)
CORS(app)

# === Página principal ===
@app.route('/')
def index():
    return render_template('index.html')

# === Cifrado de imagen ===
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

# === Historial de imágenes ===
@app.route('/historial')
def historial():
    documentos = list(coleccion.find({}, {'_id': 0}))
    return render_template('historial.html', documentos=documentos)

# === Descifrado protegido por JWT ===
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
        if datos['email'] != usuario:
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

# === Redireccionamiento a Google ===
@app.route("/login_google")
def login_google():
    google_auth_endpoint = "https://accounts.google.com/o/oauth2/auth"
    redirect_uri = "http://127.0.0.1:5000/login"
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "response_type": "code",
        "access_type": "offline",
        "prompt": "consent"
    }
    return redirect(f"{google_auth_endpoint}?{urlencode(params)}")

# === Callback de Google ===
@app.route("/login")
def login():
    code = request.args.get("code")
    if not code:
        return "❌ Código no proporcionado", 400

    # Intercambiar código por token
    token_endpoint = "https://oauth2.googleapis.com/token"
    data = {
        "code": code,
        "client_id": os.getenv("GOOGLE_CLIENT_ID"),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET"),
        "redirect_uri": "http://127.0.0.1:5000/login",
        "grant_type": "authorization_code"
    }

    response = requests.post(token_endpoint, data=data)
    token_info = response.json()
    access_token = token_info.get("access_token")

    if not access_token:
        return "❌ No se pudo obtener el access_token", 400

    # Obtener información del usuario
    user_info = requests.get(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"}
    ).json()

    email = user_info.get("email")
    nombre = user_info.get("name")

    # Verificar usuario en la base de datos
    usuario = db['usuarios'].find_one({"email": email})
    if not usuario:
        usuario = {
            "email": email,
            "nombre": nombre,
            "rol": "usuario"
        }
        db['usuarios'].insert_one(usuario)

    # Crear token JWT
    token = jwt.encode(
        {"email": email, "rol": usuario["rol"], "exp": datetime.utcnow() + timedelta(hours=2)},
        SECRET_KEY,
        algorithm="HS256"
    )

    return jsonify({
        "mensaje": f"✅ Bienvenido {nombre}",
        "token": token,
        "rol": usuario["rol"]
    })


# === Ejecutar servidor Flask ===
if __name__ == '__main__':
    app.run(debug=True)
