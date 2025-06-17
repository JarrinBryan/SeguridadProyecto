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
    token = request.args.get('token') or None

    if not token:
        return redirect(url_for('index'))

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = decoded.get("usuario")

        usuario_doc = db.usuarios.find_one({"email": email})
        if not usuario_doc:
            return "Usuario no encontrado", 404

        nombre = usuario_doc.get("nombre", email)
        foto = usuario_doc.get("foto", "https://www.gravatar.com/avatar/?d=mp")  # Imagen por defecto si no tiene foto
        rol = usuario_doc.get("rol", "usuario")

        return render_template('index.html', nombre=nombre, foto=foto, rol=rol, email=email)

    except jwt.ExpiredSignatureError:
        return "Token expirado. Inicia sesión nuevamente.", 401
    except jwt.InvalidTokenError:
        return "Token inválido", 403




# Cifrar imagen
@app.route('/cifrar', methods=['POST'])
def cifrar():
    try:
        imagen = request.files['imagen']
        llave = request.form['llave']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']

        # Validar duplicado
        existe = coleccion.find_one({
            'usuario': usuario,
            'nombre_imagen': nombre_imagen
        })

        if existe:
            return jsonify({'error': '❌ Ya existe una imagen con ese nombre. Usa otro nombre único.'}), 400

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

# Nueva colección para bloqueos
bloqueos = db['bloqueos']

# Página para descifrar
@app.route('/descifrar', methods=['GET', 'POST'])
def descifrar():
    if request.method == 'GET':
        token = request.args.get('token')
        if not token:
            return redirect(url_for('index'))

        try:
            datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            email = datos['usuario']

            # Buscar imágenes del usuario
            imagenes = list(coleccion.find({"usuario": email}, {"_id": 0, "nombre_imagen": 1}))
            return render_template('descifrar.html', imagenes=imagenes, usuario=email)

        except jwt.ExpiredSignatureError:
            return "Token expirado", 401
        except jwt.InvalidTokenError:
            return "Token inválido", 403

    # POST = intento de descifrado
    try:
        token = request.form['token']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']
        llave = request.form['llave']

        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if datos['usuario'] != usuario:
            return jsonify({'error': '❌ El token no pertenece a ese usuario.'}), 403

        ahora = datetime.utcnow()
        bloqueo = bloqueos.find_one({'usuario': usuario, 'imagen': nombre_imagen})

        if bloqueo and bloqueo.get('bloqueado_hasta') and ahora < bloqueo['bloqueado_hasta']:
            segundos = int((bloqueo['bloqueado_hasta'] - ahora).total_seconds())
            return jsonify({'error': f'⏳ Imagen bloqueada temporalmente. Intenta en {segundos} segundos.'}), 403

        doc = coleccion.find_one({
            'usuario': usuario,
            'nombre_imagen': nombre_imagen
        })

        if not doc:
            return jsonify({'error': 'Imagen no encontrada para ese usuario.'}), 404

        try:
            cifrada = doc['imagen_cifrada']
            imagen_bytes = descifrar_imagen(cifrada, llave)

            # Si fue exitoso, eliminamos el bloqueo si existe
            bloqueos.delete_one({'usuario': usuario, 'imagen': nombre_imagen})

            imagen_base64 = base64.b64encode(imagen_bytes).decode('utf-8')
            return jsonify({'imagen': imagen_base64})

        except Exception as e:
            print("Descifrado fallido:", e)

            # Fallo → actualizar contador
            if not bloqueo:
                bloqueos.insert_one({
                    'usuario': usuario,
                    'imagen': nombre_imagen,
                    'intentos': 1,
                    'bloqueado_hasta': None
                })
            else:
                intentos = bloqueo.get('intentos', 0) + 1
                update = {'intentos': intentos}
                if intentos >= 3:
                    update['bloqueado_hasta'] = ahora + timedelta(seconds=30)
                    update['intentos'] = 0  # reiniciar para el siguiente ciclo
                bloqueos.update_one({'_id': bloqueo['_id']}, {'$set': update})

            return jsonify({'error': '❌ Llave incorrecta o integridad comprometida.'}), 403

    except jwt.ExpiredSignatureError:
        return jsonify({'error': '❌ El token ha expirado.'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': '❌ Token inválido.'}), 401
    except Exception as e:
        print("Error general en descifrado:", e)
        return jsonify({'error': '❌ No se pudo descifrar la imagen.'}), 400

# Google login callback (POST)
@app.route('/google-login', methods=['POST'])
def google_login():
    try:
        data = request.get_json()
        token_google = data.get('credential')

        print("TOKEN recibido:", token_google)

        if not token_google:
            return jsonify({"error": "❌ Token de Google no proporcionado."}), 400

        idinfo = id_token.verify_oauth2_token(
            token_google,
            grequests.Request(),
            audience=GOOGLE_CLIENT_ID
        )

        email = idinfo['email']
        nombre = idinfo.get('name', email)
        foto = idinfo.get('picture', '')  #  AQUI se obtiene la foto

        usuarios_col = db['usuarios']
        usuario_db = usuarios_col.find_one({'email': email})

        if not usuario_db:
            usuarios_col.insert_one({
                "email": email,
                "nombre": nombre,
                "foto": foto,  #  Guardamos la foto
                "rol": "usuario",
                "claveAES": None
            })
            rol = "usuario"
        else:
            rol = usuario_db.get("rol", "usuario")

        token = jwt.encode({
            "usuario": email,
            "exp": datetime.utcnow() + timedelta(hours=2)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
            "token": token,
            "usuario": email,
            "nombre": nombre,
            "foto": foto,  # ✅ Enviamos la foto al frontend
            "redirect": "/admin" if rol == "admin" else "/inicio"
        })

    except Exception as e:
        print("Error:", e)
        return jsonify({"error": "❌ Error al autenticar"}), 500


def obtener_rol_desde_email(email):
    usuario = db.usuarios.find_one({"email": email})
    if usuario:
        return usuario.get("rol", "usuario")
    return "usuario"

@app.route('/admin')
def panel_admin():
    return render_template('admin.html', nombre="Administrador", rol="admin")

@app.route('/admin/usuarios')
def admin_usuarios():
    usuarios = list(db.usuarios.find({}, {'_id': 0}))  # sin _id
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/estadisticas')
def admin_estadisticas():
    total_usuarios = db.usuarios.count_documents({})
    total_imagenes = coleccion.count_documents({})

    # Obtener cantidad de imágenes por usuario
    pipeline = [
        {"$group": {"_id": "$usuario", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}}
    ]
    imagenes_por_usuario = list(coleccion.aggregate(pipeline))

    return render_template("admin_estadisticas.html",
                           total_usuarios=total_usuarios,
                           total_imagenes=total_imagenes,
                           imagenes_por_usuario=imagenes_por_usuario)


# Ejecutar en localhost
if __name__ == '__main__':
    app.run(host='localhost', port=5000, debug=True)
