from waitress import serve
from backend.app import app

if __name__ == "__main__":
    print("✅ Servidor iniciado en http://localhost:5000")
    serve(app, host="0.0.0.0", port=5000)
