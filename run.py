from waitress import serve
from backend.app import app
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Render define el puerto en la variable PORT
    print(f"✅ Servidor iniciado en http://0.0.0.0:{port}")
    serve(app, host="0.0.0.0", port=port)
