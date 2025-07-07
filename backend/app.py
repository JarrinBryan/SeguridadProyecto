from flask import Flask, request, render_template, jsonify, redirect, url_for, send_file
from flask_cors import CORS
from dotenv import load_dotenv
from pymongo import MongoClient
import os
import certifi
import base64
from io import BytesIO
from datetime import datetime, timedelta
import jwt
from bson import ObjectId
from google.oauth2 import id_token
from google.auth.transport import requests as grequests
import re
import traceback
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from PIL import Image
import io
from backend.crypto import cifrar_imagen_auto, descifrar_imagen_auto
from flask import make_response  
import hashlib




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

def validar_clave_segura(clave):
    if len(clave) < 6:
        return False, "La clave debe tener al menos 6 caracteres."
    if not re.search(r"[A-Z]", clave):
        return False, "La clave debe contener al menos una letra mayúscula."
    if not re.search(r"[a-z]", clave):
        return False, "La clave debe contener al menos una letra minúscula."
    if not re.search(r"[0-9]", clave):
        return False, "La clave debe contener al menos un número."
    return True, ""

def es_imagen_valida(nombre_archivo, mimetype):
    extensiones_permitidas = ['.jpg', '.jpeg', '.png']
    mimetypes_permitidos = ['image/jpeg', 'image/png']
    _, extension = os.path.splitext(nombre_archivo.lower())
    return extension in extensiones_permitidas and mimetype in mimetypes_permitidos

@app.route('/')
def index():
    return render_template('login.html', google_client_id=GOOGLE_CLIENT_ID)

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
        foto = usuario_doc.get("foto", "https://www.gravatar.com/avatar/?d=mp")
        rol = usuario_doc.get("rol", "usuario")
        return render_template('index.html', nombre=nombre, foto=foto, rol=rol, email=email)
    except jwt.ExpiredSignatureError:
        return "Token expirado. Inicia sesión nuevamente.", 401
    except jwt.InvalidTokenError:
        return "Token inválido", 403

from backend.utils import cifrar_clave, generar_hmac  # ✅ añadimos generar_hmac

@app.route('/cifrar', methods=['POST'])
def cifrar():
    try:
        imagen = request.files['imagen']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']

        if not es_imagen_valida(imagen.filename, imagen.mimetype):
            return jsonify({'error': '❌ Solo se permiten archivos .jpg, .jpeg o .png'}), 400

        if coleccion.find_one({'usuario': usuario, 'nombre_imagen': nombre_imagen}):
            return jsonify({'error': '❌ Ya existe una imagen con ese nombre. Usa otro.'}), 400

        imagen_bytes = imagen.read()
        resultado = cifrar_imagen_auto(imagen_bytes)

        # ✅ Firma HMAC con clave original
        firma_hmac = generar_hmac(resultado['imagen_cifrada'], resultado['clave'])

        # 🧠 Hash SHA-256 de la clave original
        hash_clave = hashlib.sha256(resultado['clave'].encode()).hexdigest()

        # 📦 Guardar en MongoDB (con salt incluido)
        coleccion.insert_one({
            'usuario': usuario,
            'nombre_imagen': nombre_imagen,
            'imagen_cifrada': resultado['imagen_cifrada'],
            
            'salt': resultado['salt'],  # ✅ AÑADIDO AQUÍ
            'clave_hash': hash_clave,
            'firma_hmac': firma_hmac,
            'fecha': datetime.now()
        })

        # ✅ Enviar la clave original como archivo descargable
        response = make_response(resultado['clave'])
        response.headers['Content-Type'] = 'text/plain'
        response.headers['Content-Disposition'] = 'attachment; filename=clave_AES.txt'
        return response

    except Exception as e:
        print("Error en /cifrar automático:", e)
        traceback.print_exc()
        return jsonify({'error': '❌ Fallo al cifrar la imagen.'}), 500



@app.route('/historial')
def historial():
    documentos = list(coleccion.find({}, {'_id': 0}))
    return render_template('historial.html', documentos=documentos)

bloqueos = db['bloqueos']

from backend.utils import descifrar_clave # al inicio

from backend.utils import descifrar_clave, verificar_hmac  # ✅ Asegúrate de tener esto arriba

@app.route('/descifrar', methods=['GET', 'POST'])
def descifrar():
    if request.method == 'GET':
        token = request.args.get('token')
        if not token:
            return redirect(url_for('index'))
        try:
            datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            email = datos['usuario']
            imagenes = list(coleccion.find({"usuario": email}, {"_id": 0, "nombre_imagen": 1}))
            return render_template('descifrar.html', imagenes=imagenes, usuario=email)
        except jwt.ExpiredSignatureError:
            return "Token expirado", 401
        except jwt.InvalidTokenError:
            return "Token inválido", 403

    try:
        token = request.form['token']
        usuario = request.form['usuario']
        nombre_imagen = request.form['nombre_imagen']
        llave_usuario = request.form['llave']

        datos = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        if datos['usuario'] != usuario:
            return jsonify({'error': '❌ El token no pertenece a ese usuario.'}), 403

        ahora = datetime.utcnow()
        bloqueo = bloqueos.find_one({'usuario': usuario, 'imagen': nombre_imagen})
        if bloqueo and bloqueo.get('bloqueado_hasta') and ahora < bloqueo['bloqueado_hasta']:
            segundos = int((bloqueo['bloqueado_hasta'] - ahora).total_seconds())
            return jsonify({'error': f'⏳ Imagen bloqueada temporalmente. Intenta en {segundos} segundos.'}), 403

        doc = coleccion.find_one({'usuario': usuario, 'nombre_imagen': nombre_imagen})
        if not doc:
            return jsonify({'error': 'Imagen no encontrada para ese usuario.'}), 404

        cifrada = doc['imagen_cifrada']
        salt = doc['salt']
        firma_guardada = doc['firma_hmac']
        hash_guardado = doc['clave_hash']

        # Validar el hash de la clave ingresada
        hash_ingresado = hashlib.sha256(llave_usuario.encode()).hexdigest()
        if hash_ingresado != hash_guardado:
            if not bloqueo:
                bloqueos.insert_one({
                    'usuario': usuario,
                    'imagen': nombre_imagen,
                    'intentos': 1,
                    'intentos_totales': 1,
                    'bloqueado_hasta': None
                })
            else:
                intentos = bloqueo.get('intentos', 0) + 1
                intentos_totales = bloqueo.get('intentos_totales', 0) + 1
                update = {
                    'intentos': intentos,
                    'intentos_totales': intentos_totales
                }
                if intentos >= 3:
                    update['bloqueado_hasta'] = ahora + timedelta(seconds=30)
                    update['intentos'] = 0
                bloqueos.update_one({'_id': bloqueo['_id']}, {'$set': update})

            return jsonify({'error': '⚠️ Llave incorrecta o alterada.'}), 403

        # Verificar integridad con HMAC
        if not verificar_hmac(cifrada, llave_usuario, firma_guardada):
            return jsonify({'error': '⚠️ Integridad comprometida: imagen modificada o clave incorrecta.'}), 403

        # Descifrado exitoso
        imagen_bytes = descifrar_imagen_auto(cifrada, llave_usuario, salt)
        bloqueos.delete_one({'usuario': usuario, 'imagen': nombre_imagen})

        imagen_base64 = base64.b64encode(imagen_bytes).decode('utf-8')
        return jsonify({'imagen': imagen_base64})

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

@app.route('/descargar_reporte')
def descargar_reporte():
    try:
        # Obtener datos desde Mongo
        pipeline = [{"$group": {"_id": "$usuario", "total": {"$sum": 1}}}]
        resultados = list(coleccion.aggregate(pipeline))
        total_usuarios = len(resultados)
        total_imagenes = coleccion.count_documents({})

        # Crear PDF en memoria
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        elements = []

        # Título y fecha
        elements.append(Paragraph("📊 <b>Reporte de Estadísticas del Sistema</b>", styles['Title']))
        elements.append(Spacer(1, 12))
        elements.append(Paragraph(f"📅 Fecha: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", styles['Normal']))
        elements.append(Spacer(1, 20))

        # Tabla de resumen
        resumen_data = [
            ["Total de usuarios registrados", total_usuarios],
            ["Total de imágenes cifradas", total_imagenes]
        ]
        resumen_table = Table(resumen_data, colWidths=[300, 150])
        resumen_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightblue),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ]))
        elements.append(Paragraph("<b>Resumen general:</b>", styles['Heading2']))
        elements.append(resumen_table)
        elements.append(Spacer(1, 20))

        # Tabla por usuario
        tabla_data = [["Usuario", "Cantidad de imágenes"]]
        for item in resultados:
            tabla_data.append([item["_id"], str(item["total"])])

        tabla = Table(tabla_data, colWidths=[300, 150])
        tabla.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 13),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
        ]))
        elements.append(Paragraph("<b>Imágenes por usuario:</b>", styles['Heading2']))
        elements.append(tabla)

        # Construir documento
        doc.build(elements)

        # Volver al inicio del buffer
        buffer.seek(0)

        return send_file(
            buffer,
            as_attachment=True,
            download_name='reporte_estadisticas.pdf',
            mimetype='application/pdf'
        )

    except Exception as e:
          print("⚠️ Error al generar el PDF:", e)
    traceback.print_exc()  # <- esto muestra el error completo en consola
    return jsonify({'error': 'No se pudo generar el PDF'}), 500

# Ejecutar en localhost
#if __name__ == '__main__':
   # app.run(host='localhost', port=5000, debug=True)