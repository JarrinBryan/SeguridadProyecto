from flask import Flask, request, render_template, jsonify
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
import jwt  # Asegúrate de que es de PyJWT, no del paquete 'jwt' incorrecto
from bson import ObjectId

# === Cargar variables de entorno ===
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")
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

# === Login y generación de token JWT ===
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form['usuario']

        token = jwt.encode(
            {"usuario": usuario, "exp": datetime.utcnow() + timedelta(hours=2)},
            SECRET_KEY,
            algorithm="HS256"
        )

        return render_template('login.html', token=token, usuario=usuario)

    return render_template('login.html')

# === Función para validar token ===
def obtener_usuario_desde_token(token):
    try:
        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return datos['usuario']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

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

        # Validar el token
        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if datos['usuario'] != usuario:
            return jsonify({'error': 'El token no pertenece a ese usuario.'}), 403

        # Buscar la imagen cifrada
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


# === Ejecutar servidor Flask ===
if __name__ == '__main__':
    app.run(debug=True)
