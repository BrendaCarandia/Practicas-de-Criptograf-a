from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_login import LoginManager
from crypto_utils import load_authority_public_key, load_authority_private_key
import os 

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login' # Ruta para iniciar sesión
login_manager.login_message_category = 'info' # Categoría de mensaje para flash

# Cargar las llaves de la autoridad de votación
authority_private_key = None
authority_public_key = None

try:
    authority_private_key = load_authority_private_key()
    authority_public_key = load_authority_public_key()
    print("Llaves de la autoridad cargadas correctamente.")
except FileNotFoundError:
    print("Llaves de la autoridad no encontradas. Asegúrese de generarlas antes de iniciar la aplicación.")
except Exception as e:
    print(f"Error al cargar las llaves de la autoridad: {e}")
    
from routes import *  
from models import * 

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create database tables if they don't exist
    app.run(debug=True)