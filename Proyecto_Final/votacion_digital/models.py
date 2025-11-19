from app import db, login_manager
from flask_login import UserMixin
import hashlib
import os
import base64
from datetime import datetime

# Función para cargar el usuario para Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)   
    user_type = db.Column(db.String(20), nullable=False, default='conventional')  # 'admin' o 'voter'
    # Campos para llaves RSA (solo para usuarios convencionales)
    public_key = db.Column(db.Text, nullable=True) # Clave pública RSA en formato PEM
    private_key_encrypted = db.Column(db.Text, nullable=True) # Clave privada RSA encriptada

    # Función auxiliar para generar el hash con Shake128
    def _generate_shake128_hash(self, data, salt):
        # Codificamos la sal y los datos a bytes antes de hashear
        hasher = hashlib.shake_128()
        hasher.update(salt.encode('utf-8'))
        hasher.update(data.encode('utf-8'))
        return hasher.hexdigest(32)  # Genera un hash de 256 bits (32 bytes)
    
    def set_password(self, password):
        # Aquí usaremos Shake128 para el hashing de la contraseña
        # Generar una sal aleatoria
        self.salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')[:32]
        self.password_hash = self._generate_shake128_hash(password, self.salt)

    def check_password(self, password):
        # Regenerar el hash con la contraseña y la sal 
        # Comparar con el hash almacenado
        return self.password_hash == self._generate_shake128_hash(password, self.salt)

    def __repr__(self):
        return f"User('{self.username}', '{self.user_type}')"
    

class BlindSignatureToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # El hash del mensaje puede ser grande (representado como decimal string)
    # y múltiples usuarios pueden tener el mismo 'message' (por ejemplo, la misma
    # opción de voto). No debe ser UNIQUE globalmente. Usamos Text para evitar
    # truncamientos.
    message_hash = db.Column(db.Text, nullable=False)
    signature_token = db.Column(db.Text, nullable=False) # La firma ciega descegada (representada como decimal string)
    is_used = db.Column(db.Boolean, default=False) # Para evitar doble voto
    user = db.relationship('User', backref=db.backref('tokens', lazy=True))

    def __repr__(self):
        return f"BlindSignatureToken(User ID: {self.user_id}, Hash: {str(self.message_hash)[:10]}..., Used: {self.is_used})"

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False) # Para saber quién votó (si se permite)
    vote_option = db.Column(db.String(100), nullable=False) # La opción de voto elegida
    signature = db.Column(db.Text, nullable=False) # La firma ciega descegada
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('votes', lazy=True))

    def __repr__(self):
        return f"Vote(User ID: {self.user_id}, Option: {self.vote_option})"