from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient
from crypto import cifrar_imagen
import os
from datetime import datetime  # <--- arriba al inicio del archivo
import certifi  # para conexión segura
from flask import send_file
from io import BytesIO
from crypto import descifrar_imagen  # asegúrate de importar
from bson import ObjectId

# === Cargar variables del entorno ===
load_dotenv()
MONGO_URI = os.getenv("MONGO_URI")

# === Conectar con MongoDB con TLS ===
client = MongoClient(MONGO_URI, tlsCAFile=certifi.where())
db = client['ProyectoS']
coleccion = db['imagenes']

# === Iniciar Flask ===
app = Flask(__name__)
CORS(app)

# === Rutas ===

@app.route('/')
def index():
    return render_template('index.html')

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
        return jsonify({'error': '❌ Ocurrió un error al cifrar o guardar la imagen.'}), 500

@app.route('/historial')
def historial():
    documentos = list(coleccion.find({}, {'_id': 0}))  # Excluimos _id
    return render_template('historial.html', documentos=documentos)


@app.route('/descifrar', methods=['GET', 'POST'])
def descifrar():
    if request.method == 'GET':
        return render_template('descifrar.html')

    try:
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']
        llave = request.form['llave']

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

    except Exception as e:
        print("Error al descifrar:", e)
        return jsonify({'error': 'No se pudo descifrar. ¿La llave es correcta?'}), 400


# === Ejecutar servidor ===
if __name__ == '__main__':
    app.run(debug=True)
