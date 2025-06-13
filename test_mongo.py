from pymongo import MongoClient
import certifi

uri = "mongodb+srv://ferchojarrin26:247wIHluJZ5lQFOf@cluster0.voljjnx.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

print("⏳ Intentando conectar a MongoDB Atlas...")

try:
    client = MongoClient(uri, serverSelectionTimeoutMS=5000, tlsCAFile=certifi.where())
    # Forzamos una operación para probar conexión
    client.admin.command("ping")
    print("✅ Conexión exitosa a MongoDB Atlas")
except Exception as e:
    print("❌ Falló la conexión a MongoDB Atlas:")
    print(e)
