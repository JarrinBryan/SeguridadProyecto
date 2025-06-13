<<<<<<< HEAD
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
=======
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
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['ProyectoS']
coleccion = db['imagenes']

<<<<<<< HEAD
# === Iniciar aplicación Flask ===
app = Flask(__name__)
CORS(app)

# === Página principal ===
@app.route('/')
def index():
    return render_template('index.html')

# === Cifrado de imagen ===
=======
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
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
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
<<<<<<< HEAD

=======
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
    except Exception as e:
        print("Error en /cifrar:", e)
        return jsonify({'error': '❌ Error al cifrar o guardar la imagen.'}), 500

<<<<<<< HEAD
# === Historial de imágenes ===
=======
# Ver historial
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
@app.route('/historial')
def historial():
    documentos = list(coleccion.find({}, {'_id': 0}))
    return render_template('historial.html', documentos=documentos)

<<<<<<< HEAD
# === Descifrado protegido por JWT ===
=======
# Página para descifrar
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
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
<<<<<<< HEAD
        if datos['email'] != usuario:
=======
        if datos['usuario'] != usuario:
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
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

<<<<<<< HEAD
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
=======
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
>>>>>>> 5c1797a0140570cfea40dd90826fd87a41d5f4ee
