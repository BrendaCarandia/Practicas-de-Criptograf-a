# Reporte de Proyecto: Sistema de Votación Digital con Firma Ciega

## Tabla de Contenidos

1. [Introducción](#1-introducción)
   - [1.1. Resumen del Proyecto](#11-resumen-del-proyecto)
   - [1.2. Objetivos del Proyecto](#12-objetivos-del-proyecto)
   - [1.3. Requisitos Clave](#13-requisitos-clave)

2. [Justificación del Stack Tecnológico](#2-justificación-del-stack-tecnológico)
   - [2.1. Backend: Python y Flask](#21-backend-python-y-flask)
   - [2.2. Base de Datos: SQLite](#22-base-de-datos-sqlite)
   - [2.3. Criptografía: cryptography, hashlib](#23-criptografía-cryptography-hashlib)
   - [2.4. Formularios y Autenticación: Flask-WTF, Flask-Login](#24-formularios-y-autenticación-flask-wtf-flask-login)
   - [2.5. Frontend: HTML, CSS, JavaScript (Vanilla JS)](#25-frontend-html-css-javascript-vanilla-js)

3. [Preparación del Entorno de Desarrollo](#3-preparación-del-entorno-de-desarrollo)
   - [3.1 MacOS](#31-MacOS)
   - [3.1.1 Xcode Command Line Tools](#311-xcode-command-line-tools)
   - [3.1.2 Homebrew](#312-homebrew)
   - [3.1.3 Python 3](#313-python-3)
   - [3.1.4 Entorno Virtual (venv)](#314-entorno-virtual-venv)
   - [3.1.5 Instalación de Librerías Python](#315-instalación-de-librerías-python)
   - [3.2 Windows](#32-windows)
   - [3.2.1 Microsoft C++ Build Tools](#321-microsoft-c-build-tools)
   - [3.2.2 Python](#322-python)
   - [3.2.3 Entorno Virtual (venv)](#323-entorno-virtual-venv)
   - [3.2.4 Instalación de Librerías Python](#324-instalación-de-librerías-python)
   - [3.2.5. Versiones de los paquetes instalados](#324-versiones-de-los-paqutes-instalados)

4. [Estructura del Proyecto](#4-estructura-del-proyecto)

5. [Implementación Detallada del Backend](#5-implementación-detallada-del-backend)
   - [5.1. config.py - Configuración de la Aplicación](#51-configpy---configuración-de-la-aplicación)
   - [5.2. app.py - Núcleo de la Aplicación Flask](#52-apppy---núcleo-de-la-aplicación-flask)
   - [5.3. models.py - Modelos de Base de Datos](#53-modelspy---modelos-de-base-de-datos)
   - [5.4. forms.py - Formularios de Autenticación](#54-formspy---formularios-de-autenticación)
   - [5.5. crypto_utils.py - Funciones Criptográficas](#55-crypto_utilspy---funciones-criptográficas)
   - [5.6. routes.py - Lógica de Rutas y Negocio](#56-routespy---lógica-de-rutas-y-negocio)

6. [Implementación Detallada del Frontend](#6-implementación-detallada-del-frontend)
   - [6.1. templates/base.html - Plantilla Base](#61-templatesbasehtml---plantilla-base)
   - [6.2. templates/home.html - Página de Inicio](#62-templateshomehtml---página-de-inicio)
   - [6.3. templates/register.html - Formulario de Registro](#63-templatesregisterhtml---formulario-de-registro)
   - [6.4. templates/login.html - Formulario de Inicio de Sesión](#64-templatesloginhtml---formulario-de-inicio-de-sesión)
   - [6.5. templates/user_dashboard.html - Panel de Usuario Convencional](#65-templatesuser_dashboardhtml---panel-de-usuario-convencional)
   - [6.6. templates/admin_dashboard.html - Panel de Administrador](#66-templatesadmin_dashboardhtml---panel-de-administrador)
   - [6.7. static/css/style.css - Estilos CSS](#67-staticcssstylecss---estilos-css)
   - [6.8. static/js/main.js - JavaScript](#68-staticjsmainjs---javascript)

7. [Conceptos Criptográficos Clave](#7-conceptos-criptográficos-clave)
   - [7.1. Hashing de Contraseñas con SHAke128 y Salt](#71-hashing-de-contraseñas-con-shake128-y-salt)
   - [7.2. Criptografía RSA (Clave Pública/Privada)](#72-criptografía-rsa-clave-públicaprivada)
   - [7.3. Firma Digital RSA](#73-firma-digital-rsa)
   - [7.4. Firma Ciega RSA](#74-firma-ciega-rsa)

8. [Pruebas y Verificación](#8-pruebas-y-verificación)
   - [8.1. Proceso de Pruebas](#81-proceso-de-pruebas)
   - [8.2. Uso de la Clave Pública para Auditoría Externa](#82-uso-de-la-clave-pública-para-auditoría-externa)

9. [Consideraciones y Mejoras Futuras](#9-consideraciones-y-mejoras-futuras)

10. [Conclusión](#10-conclusión)


---

## 1. Introducción

### 1.1. Resumen del Proyecto

El presente reporte detalla la implementación de un Sistema de Votación Digital con Firma Ciega, desarrollado como un proyecto a nivel de licenciatura. El objetivo principal es crear una plataforma web funcional que demuestre los principios de autenticación segura, gestión de usuarios con roles, y, fundamentalmente, la aplicación de criptografía avanzada mediante la firma ciega RSA para garantizar la privacidad y la integridad del voto. El sistema está diseñado para operar de manera local en un entorno de desarrollo.

### 1.2. Objetivos del Proyecto

Los objetivos específicos de este proyecto incluyen:

- Desarrollar un portal de autenticación robusto con gestión de usuarios y roles (convencional y administrador).
- Implementar un sistema de registro que genere y gestione pares de llaves RSA para usuarios convencionales.
- Utilizar el algoritmo de hashing SHAke128 con sal para el almacenamiento seguro de contraseñas.
- Integrar la funcionalidad de firma ciega RSA para permitir a los usuarios votar de forma anónima, pero verificable.
- Proporcionar una interfaz de votación para usuarios convencionales y un panel de estadísticas para administradores.
- Asegurar que el despliegue y la complejidad del sistema sean adecuados para un proyecto de licenciatura.

### 1.3. Requisitos Clave

Los requisitos funcionales y no funcionales considerados fueron:

- **Autenticación**: Portal de usuario/contraseña, base de datos con contraseñas hasheadas (SHAke128).
- **Roles**: Usuario convencional y administrador.
- **Gestión de Llaves**: Generación de pares de llaves RSA para usuarios convencionales, almacenamiento seguro de la clave privada (encriptada) y descarga de la clave pública.
- **Votación**: Portal de votación de opción múltiple con validación mediante firma digital.
- **Firma Ciega**: Implementación del protocolo de firma ciega para la privacidad del voto.
- **Administración**: Pantalla de estadísticas de votación para administradores.
- **Simplicidad**: Despliegue local y complejidad adecuada para un proyecto de licenciatura.


---

## 2. Justificación del Stack Tecnológico

La elección del stack tecnológico se basó en la necesidad de equilibrar la funcionalidad requerida con la simplicidad y la curva de aprendizaje para un proyecto de licenciatura.

### 2.1. Backend: Python y Flask

**Python**: Lenguaje de programación de alto nivel, conocido por su legibilidad y versatilidad. Su amplio ecosistema de librerías criptográficas (hashlib, cryptography) lo hace ideal para este proyecto.

**Flask**: Un microframework web ligero y flexible. Su naturaleza minimalista permite construir aplicaciones web de forma rápida y con un control granular, sin la sobrecarga de frameworks más grandes, lo que es perfecto para un proyecto académico.

### 2.2. Base de Datos: SQLite

**SQLite**: Una base de datos embebida basada en archivos. No requiere un servidor de base de datos separado, lo que facilita enormemente la configuración, el desarrollo y el despliegue local. Es ideal para proyectos pequeños y para propósitos de demostración.

### 2.3. Criptografía: cryptography, hashlib

**hashlib** (Python estándar): Proporciona implementaciones de algoritmos de hash seguros, incluyendo SHAke128, que es un requisito clave del proyecto.

**cryptography**: Una librería moderna y robusta para Python que ofrece primitivas criptográficas de bajo y alto nivel. Es esencial para la generación y gestión de llaves RSA, encriptación/desencriptación, firma digital y para la implementación de la firma ciega.

### 2.4. Formularios y Autenticación: Flask-WTF, Flask-Login

**Flask-WTF**: Extensión de Flask que integra WTForms, facilitando la creación, validación y protección contra ataques CSRF (Cross-Site Request Forgery) de formularios web.

**Flask-Login**: Extensión que simplifica la gestión de sesiones de usuario, inicio/cierre de sesión y protección de rutas para usuarios autenticados.

### 2.5. Frontend: HTML, CSS, JavaScript (Vanilla JS)

**HTML**: Para estructurar el contenido de las páginas web.

**CSS**: Para estilizar la interfaz de usuario, manteniendo un diseño limpio y funcional.

**JavaScript (Vanilla JS)**: Para añadir interactividad en el cliente, especialmente para el flujo de votación asíncrono (AJAX) y la gestión de la interfaz de usuario sin recargar la página. Se evitó el uso de frameworks de frontend complejos para mantener la simplicidad del proyecto.




---

## 3. Preparación del Entorno de Desarrollo

### 3.1 MacOS

Para configurar el entorno en una MacBook, se siguieron los siguientes pasos:

#### 3.1.1 Xcode Command Line Tools 

&nbsp;

**Propósito:** Proporciona compiladores y herramientas esenciales (como gcc) que muchas librerías de Python, especialmente las criptográficas, requieren para compilar componentes nativos durante la instalación.

**Instalación:**

```bash
xcode-select --install
```

#### 3.1.2 Homebrew 

&nbsp;

**Propósito:** Gestor de paquetes para macOS que simplifica la instalación y gestión de software de desarrollo que no viene preinstalado con el sistema operativo.

**Instalación:** 

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Verificación:** 

```bash
brew --version
```

#### 3.1.3. Python 3 

&nbsp;

**Propósito:** Instalar una versión moderna de Python 3, separada de la versión preinstalada de macOS.

**Instalación:** 

```bash
brew install python
```

**Verificación:** 

```bash
python3 --version
```

#### 3.1.4. Entorno Virtual (venv) 

&nbsp;

**Propósito:** Crear un entorno aislado para las dependencias del proyecto, evitando conflictos con otras instalaciones de Python o proyectos.

**Creación y Activación:**

```bash
cd ~/Documents/
mkdir votacion_digital
cd votacion_digital
python3 -m venv venv
source venv/bin/activate
```

(El indicador `(venv)` en la terminal confirma la activación).

#### 3.1.5. Instalación de Librerías Python 

&nbsp;

**Propósito:** Instalar todas las dependencias del proyecto dentro del entorno virtual activo.

**Instalación:**

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF cryptography
```

**Verificación:** 

```bash
pip list
```

### 3.2 Windows 

Para configurar el entorno en una maquina con Windows 10/11, se siguieron los siguientes pasos:

### 3.2.1 Microsoft C++ Build Tools 

&nbsp;

**Propósito:** Proporciona compiladores y herramientas esenciales de ejecucion que utilizan librerias de Python como cryptography, para compilar componentes nativos durante su instalacion.

**Instalación:** 

Acceder a la pagina oficial de descargas de Visual Studio: *https://visualstudio.microsoft.com/es/downloads/*

Descargar "Build Tools para Visual Studio" 

Se ejecuta el programa y se selecciona la opcion de "Desarrollo para el escritorio con C++"

### 3.2.2 Python 

&nbsp;

**Propósito:** Instalar una version actual de Python 3

**Instalación:** 

Acceder a la pagina oficial de descargas de Python, para descargar la version mas reciente del instalador: 

Al ejecutarlo se selecciona la casilla "Add Python X.X to PATH" y se instala.

**Verificación:** 

```bash
python --version
```

#### 3.2.3. Entorno Virtual (venv) 

&nbsp;

**Propósito:** Crear un entorno aislado para las dependencias del proyecto, evitando conflictos con otras instalaciones de Python o proyectos.

**Creación y Activación:**

```bash
cd ~/Documents/
mkdir votacion_digital
cd votacion_digital
python -m venv venv
venv\Scripts\activate.bat
```

(El indicador `(venv)` en la terminal confirma la activación).

#### 3.2.4. Instalación de Librerías Python 

&nbsp;

**Propósito:** Instalar todas las dependencias del proyecto dentro del entorno virtual activo.

**Instalación:**

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF cryptography
```

**Verificación:** 

```bash
pip list
```

#### 3.2.5. Versiones de los paquetes instalados

&nbsp;

**Propósito:** Verificar con que versiones se están trabajando en el proyecto


| Package | Versión |
|---|---|
| blinker | 1.9.0 |
| cffi | 2.0.0 |
| click | 8.3.0 |
| colorama | 0.4.6 |
| cryptography | 46.0.3 |
| Flask | 3.1.2 |
| Flask-Login | 0.6.3 |
| Flask-SQLAlchemy | 3.1.1 |
| Flask-WTF | 1.2.2 |
| greenlet | 3.2.4 |
| itsdangerous | 2.2.0 |
| Jinja2 | 3.1.6 |
| MarkupSafe | 3.0.3 |
| pip | 25.2 |
| pycparser | 2.23 |
| SQLAlchemy | 2.0.44 |
| typing_extensions | 4.15.0 |
| Werkzeug | 3.1.3 |
| WTForms | 3.2.1 |

---


## 4. Estructura del Proyecto

La estructura de directorios y archivos del proyecto se diseñó para organizar el código de manera lógica y modular:

```
votacion_digital/
├── venv/                   # Entorno virtual de Python
├── app.py                  # Archivo principal de la aplicación Flask
├── config.py               # Configuraciones globales de la aplicación
├── models.py               # Definiciones de modelos de base de datos (SQLAlchemy)
├── routes.py               # Lógica de rutas (URLs) y manejo de solicitudes
├── forms.py                # Definiciones de formularios web (Flask-WTF)
├── crypto_utils.py         # Funciones y utilidades criptográficas
├── authority_private_key.pem # Clave privada de la autoridad de votación (generada)
├── authority_public_key.pem  # Clave pública de la autoridad de votación (generada)
├── site.db                 # Archivo de base de datos SQLite (generado)
├── templates/              # Plantillas HTML (Jinja2)
│   ├── base.html           # Plantilla base para todas las páginas
│   ├── home.html           # Página de inicio
│   ├── login.html          # Formulario de inicio de sesión
│   ├── register.html       # Formulario de registro de usuario
│   ├── user_dashboard.html # Panel para usuarios convencionales
│   └── admin_dashboard.html# Panel para administradores
└── static/                 # Archivos estáticos (CSS, JavaScript, imágenes)
    ├── css/
    │   └── style.css       # Estilos CSS de la aplicación
    └── js/
        └── main.js         # Archivos JavaScript (actualmente vacío, lógica en templates)
```

---


## 5. Implementación Detallada del Backend

### 5.1. config.py - Configuración de la Aplicación

Este archivo define las configuraciones esenciales para la aplicación Flask, incluyendo la clave secreta para seguridad y la URI de la base de datos.

```python
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'una_cadena_muy_secreta_y_dificil_de_adivinar'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///site.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
```

- **SECRET_KEY**: Fundamental para proteger sesiones, formularios y otras operaciones criptográficas. Se recomienda usar una variable de entorno en producción.
- **SQLALCHEMY_DATABASE_URI**: Especifica el uso de SQLite con un archivo site.db en la raíz del proyecto.
- **SQLALCHEMY_TRACK_MODIFICATIONS**: Desactivado para optimización.

### 5.2. app.py - Núcleo de la Aplicación Flask

El archivo app.py inicializa la aplicación Flask, las extensiones (SQLAlchemy, Flask-Login) y carga las llaves de la autoridad de votación.

```python
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from config import Config
from crypto_utils import load_authority_private_key, load_authority_public_key
import os

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Cargar las llaves de la autoridad de votación
authority_private_key = None
authority_public_key = None
try:
    authority_private_key = load_authority_private_key()
    authority_public_key = load_authority_public_key()
    print("Llaves de autoridad cargadas exitosamente.")
except FileNotFoundError:
    print("ADVERTENCIA: Las llaves de autoridad no se encontraron. Asegúrate de haberlas generado con generate_and_save_authority_keys().")
except Exception as e:
    print(f"ERROR al cargar las llaves de autoridad: {e}")

from routes import *
from models import *

if __name__ == '__main__':
    with app.app_context():
        db.create_all() # Crea las tablas de la DB si no existen
    app.run(debug=True)
```

- **Inicialización**: Crea instancias de Flask, SQLAlchemy y LoginManager.
- **Carga de Llaves de Autoridad**: Intenta cargar las claves pública y privada de la autoridad al iniciar la aplicación, crucial para el proceso de firma ciega.
- **Importaciones tardías**: `from routes import *` y `from models import *` se realizan al final para evitar problemas de importación circular.
- **db.create_all()**: Asegura que las tablas de la base de datos se creen al ejecutar app.py en modo de desarrollo.

### 5.3. models.py - Modelos de Base de Datos

Define la estructura de las tablas en la base de datos utilizando SQLAlchemy.

```python
from app import db, login_manager
from flask_login import UserMixin
import hashlib
import os
import base64
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    salt = db.Column(db.String(32), nullable=False)
    user_type = db.Column(db.String(20), nullable=False, default='conventional')
    public_key = db.Column(db.Text, nullable=True)
    private_key_encrypted = db.Column(db.Text, nullable=True)

    def _generate_shake128_hash(self, data, salt):
        hasher = hashlib.shake_128()
        hasher.update(salt.encode('utf-8'))
        hasher.update(data.encode('utf-8'))
        return hasher.hexdigest(32)

    def set_password(self, password):
        self.salt = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')[:32]
        self.password_hash = self._generate_shake128_hash(password, self.salt)

    def check_password(self, password):
        return self.password_hash == self._generate_shake128_hash(password, self.salt)

    def __repr__(self):
        return f"User('{self.username}', '{self.user_type}')"

class BlindSignatureToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message_hash = db.Column(db.String(64), nullable=False, unique=True)
    signature_token = db.Column(db.Text, nullable=False) # Almacena el token de firma ciega descegado
    is_used = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('tokens', lazy=True))

    def __repr__(self):
        return f"BlindSignatureToken(User ID: {self.user_id}, Hash: {self.message_hash[:10]}..., Used: {self.is_used})"

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    vote_option = db.Column(db.String(100), nullable=False)
    signature = db.Column(db.Text, nullable=False) # Firma digital del usuario sobre el voto
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user = db.relationship('User', backref=db.backref('votes', lazy=True))

    def __repr__(self):
        return f"Vote(User ID: {self.user_id}, Option: {self.vote_option})"
```

**User**:
- **UserMixin**: Proporciona métodos para Flask-Login.
- **password_hash, salt**: Almacenan el hash de la contraseña (SHAke128) y una sal única por usuario.
- **user_type**: Distingue entre 'conventional' y 'admin'.
- **public_key, private_key_encrypted**: Almacenan las llaves RSA del usuario convencional. La privada está encriptada con una clave derivada de la contraseña del usuario.
- **set_password, check_password**: Métodos para hashear y verificar contraseñas usando SHAke128 con sal.

**BlindSignatureToken**:
- Representa un token de firma ciega emitido por la autoridad para un usuario y una opción de voto específica.
- **message_hash**: Hash del mensaje (opción de voto) que fue firmado ciegamente.
- **signature_token**: La firma ciega descegada (el token).
- **is_used**: Flag para prevenir el doble voto.

**Vote**:
- Almacena el voto final de un usuario.
- **vote_option**: La opción elegida.
- **signature**: La firma digital del usuario sobre el voto, garantizando autenticidad e integridad.

### 5.4. forms.py - Formularios de Autenticación

Define los formularios de registro e inicio de sesión utilizando Flask-WTF para facilitar la validación y la seguridad.

```python
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from models import User

class RegistrationForm(FlaskForm):
    username = StringField('Nombre de Usuario',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    confirm_password = PasswordField('Confirmar Contraseña',
                                     validators=[DataRequired(), EqualTo('password')])
    user_type = SelectField('Tipo de Usuario',
                            choices=[('conventional', 'Usuario Convencional'), ('admin', 'Administrador')],
                            validators=[DataRequired()])
    submit = SubmitField('Registrarse')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Ese nombre de usuario ya está en uso. Por favor, elige uno diferente.')

class LoginForm(FlaskForm):
    username = StringField('Nombre de Usuario',
                           validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Contraseña', validators=[DataRequired()])
    remember = BooleanField('Recordarme')
    submit = SubmitField('Iniciar Sesión')
```

- **RegistrationForm**: Incluye campos para nombre de usuario, contraseña, confirmación de contraseña y tipo de usuario. Incorpora validadores como DataRequired, Length y EqualTo. Un validador personalizado validate_username verifica la unicidad del nombre de usuario en la base de datos.
- **LoginForm**: Contiene campos para nombre de usuario, contraseña y una opción "Recordarme".

### 5.5. crypto_utils.py - Funciones Criptográficas

Este archivo centraliza todas las operaciones criptográficas del proyecto, desde el hashing de contraseñas hasta la firma ciega RSA.

```python
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import hashlib
import os
import base64
import random
import math

# --- Funciones Auxiliares Matemáticas ---
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

def modinv(a, m):
    m0 = m
    x0 = 0
    x1 = 1
    if m == 1: return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0: x1 = x1 + m0
    return x1

# --- Generación y Gestión de Llaves RSA (Usuario) ---
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    pem_private_key = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
    pem_public_key = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return pem_private_key.decode('utf-8'), pem_public_key.decode('utf-8')

def encrypt_private_key(private_key_pem, passphrase):
    key_material = hashlib.sha256(passphrase.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    fernet = Fernet(fernet_key)
    encrypted_private_key = fernet.encrypt(private_key_pem.encode('utf-8'))
    return encrypted_private_key.decode('utf-8')

def decrypt_private_key(encrypted_private_key_str, passphrase):
    key_material = hashlib.sha256(passphrase.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    fernet = Fernet(fernet_key)
    try:
        decrypted_private_key = fernet.decrypt(encrypted_private_key_str.encode('utf-8'))
        return decrypted_private_key.decode('utf-8')
    except Exception as e:
        print(f"Error al desencriptar la clave privada: {e}")
        return None

def load_private_key_from_pem(pem_data, password=None):
    return serialization.load_pem_private_key(pem_data.encode('utf-8'), password=password.encode('utf-8') if password else None, backend=default_backend())

def load_public_key_from_pem(pem_data):
    return serialization.load_pem_public_key(pem_data.encode('utf-8'), backend=default_backend())

# --- Generación y Gestión de Llaves RSA (Autoridad) ---
def generate_and_save_authority_keys(private_path="authority_private_key.pem", public_path="authority_public_key.pem"):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(f"Llaves de autoridad generadas y guardadas en {private_path} y {public_path}")

def load_authority_private_key(path="authority_private_key.pem"):
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return private_key

def load_authority_public_key(path="authority_public_key.pem"):
    with open(path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    return public_key

# --- Funciones para Firma Ciega RSA ---
def hash_message_to_int(message):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode('utf-8'))
    message_hash_bytes = digest.finalize()
    return int.from_bytes(message_hash_bytes, 'big')

def blind_message(message_hash_int, public_key_authority):
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    while True:
        r = random.randrange(2, n - 1)
        if gcd(r, n) == 1: break
    blinded_message_int = (message_hash_int * pow(r, e, n)) % n
    return blinded_message_int, r

def sign_blinded_message(blinded_message_int, private_key_authority):
    private_numbers = private_key_authority.private_numbers()
    n = private_numbers.n
    d = private_numbers.d
    signed_blinded_message_int = pow(blinded_message_int, d, n)
    return signed_blinded_message_int

def unblind_signature(signed_blinded_message_int, r, public_key_authority):
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n
    r_inv = modinv(r, n)
    unblinded_signature_int = (signed_blinded_message_int * r_inv) % n
    return unblinded_signature_int

def verify_blind_signature(message_hash_int, unblinded_signature_int, public_key_authority):
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    return message_hash_int == pow(unblinded_signature_int, e, n)

# --- Firma y Verificación Digital Estándar ---
def sign_message(private_key_pem, message, passphrase=None):
    private_key = load_private_key_from_pem(private_key_pem, password=passphrase)
    signer = private_key.signer(padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    signer.update(message.encode('utf-8'))
    return base64.b64encode(signer.finalize()).decode('utf-8')

def verify_signature(public_key_pem, message, signature_b64):
    public_key = load_public_key_from_pem(public_key_pem)
    verifier = public_key.verifier(base64.b64decode(signature_b64), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    verifier.update(message.encode('utf-8'))
    try:
        verifier.verify()
        return True
    except Exception:
        return False
```

Hashing: La lógica de SHAke128 se encapsula en el modelo User, pero hashlib es la base.
Generación de Llaves RSA: generate_rsa_key_pair() crea un par de llaves de 2048 bits.
Encriptación de Clave Privada: encrypt_private_key() y decrypt_private_key() usan cryptography.fernet con una clave derivada (mediante SHA256) de la contraseña del usuario. Nota de seguridad: Para producción, se usaría un KDF más robusto como PBKDF2HMAC con una sal única.
Llaves de Autoridad: generate_and_save_authority_keys(), load_authority_private_key(), load_authority_public_key() gestionan el par de llaves RSA de la entidad que emitirá las firmas ciegas.
Firma Ciega RSA:
gcd, modinv: Funciones matemáticas auxiliares para las operaciones modulares.
hash_message_to_int: Convierte el hash SHA256 de un mensaje a un entero, necesario para RSA.
blind_message: Implementa el cegado del mensaje con la clave pública de la autoridad.
sign_blinded_message: La autoridad firma el mensaje cegado con su clave privada.
unblind_signature: El votante descega la firma para obtener la firma válida del mensaje original.
verify_blind_signature: Verifica la firma ciega descegada con la clave pública de la autoridad.
- **Firma Digital Estándar**: sign_message() y verify_signature() permiten a los usuarios firmar sus votos con su clave privada y verificar estas firmas con su clave pública.

### 5.6. routes.py - Lógica de Rutas y Negocio

Este archivo contiene toda la lógica de negocio de la aplicación, definiendo las URLs y las funciones que las manejan.

```python
from flask import render_template, url_for, flash, redirect, request, send_file, jsonify
from app import app, db, login_manager, authority_private_key, authority_public_key
from forms import RegistrationForm, LoginForm
from models import User, BlindSignatureToken, Vote
from flask_login import login_user, current_user, logout_user, login_required
from crypto_utils import (generate_rsa_key_pair, encrypt_private_key, decrypt_private_key,
                          blind_message, sign_blinded_message, unblind_signature,
                          verify_blind_signature, hash_message_to_int, sign_message,
                          verify_signature)
import io 
from datetime import datetime
from collections import Counter

AVAILABLE_VOTE_OPTIONS = ['Candidato A', 'Candidato B', 'Candidato C', 'Candidato D']

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', title='Inicio')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, user_type=form.user_type.data)
        user.set_password(form.password.data)

        if user.user_type == 'conventional':
            private_key_pem, public_key_pem = generate_rsa_key_pair()
            user.public_key = public_key_pem
            user.private_key_encrypted = encrypt_private_key(private_key_pem, form.password.data)

        db.session.add(user)
        db.session.commit()
        flash(f'¡Cuenta creada para {form.username.data}! Ahora puedes iniciar sesión.', 'success')

        if user.user_type == 'conventional':
            return redirect(url_for('download_public_key', user_id=user.id))
        else:
            return redirect(url_for('login'))
    return render_template('register.html', title='Registro', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('¡Inicio de sesión exitoso!', 'success')
            return redirect(next_page or url_for('dashboard'))
        else:
            flash('Inicio de sesión fallido. Por favor, verifica tu nombre de usuario y contraseña.', 'danger')
    return render_template('login.html', title='Iniciar Sesión', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('Has cerrado sesión exitosamente.', 'info')
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    if current_user.user_type == 'admin':
        all_votes = Vote.query.all()
        total_votes = len(all_votes)
        vote_counts = Counter(vote.vote_option for vote in all_votes)
        statistics = [{'option': option, 'count': count} for option, count in vote_counts.items()]
        statistics.sort(key=lambda x: x['count'], reverse=True)
        return render_template('admin_dashboard.html', title='Panel de Administrador', statistics=statistics, total_votes=total_votes)
    else:
        user_votes = Vote.query.filter_by(user_id=current_user.id).all()
        pending_tokens = BlindSignatureToken.query.filter_by(user_id=current_user.id, is_used=False).all()
        return render_template('user_dashboard.html', title='Panel de Usuario', user_votes=user_votes, pending_tokens=pending_tokens, available_options=AVAILABLE_VOTE_OPTIONS)
    

@app.route("/request_blind_signature_token", methods=['POST'])
@login_required
def request_blind_signature_token():
    if current_user.user_type != 'conventional':
        return jsonify({'status': 'error', 'message': 'Solo los usuarios convencionales pueden solicitar tokens de firma ciega.'}), 403

    existing_vote = Vote.query.filter_by(user_id=current_user.id).first()
    if existing_vote:
        return jsonify({'status': 'error', 'message': 'Ya has emitido tu voto. Solo se permite un voto por usuario.'}), 403

    data = request.get_json()
    vote_option = data.get('vote_option')

    if not vote_option:
        return jsonify({'status': 'error', 'message': 'Opción de voto no proporcionada.'}), 400


    message_hash_int = hash_message_to_int(vote_option)
    message_hash_str = str(message_hash_int)

    existing_token = BlindSignatureToken.query.filter_by(user_id=current_user.id, message_hash=message_hash_str).first()
    if existing_token and existing_token.is_used:
        return jsonify({'status': 'error', 'message': 'Ya has votado con esta opción o tienes un token usado.'}), 400
    elif existing_token and not existing_token.is_used:
        return jsonify({'status': 'error', 'message': 'Ya tienes un token de firma ciega pendiente para esta opción. Utilízalo.',
                        'signature_token': existing_token.signature_token,
                        'vote_option': vote_option}), 200


    blinded_message_int, r = blind_message(message_hash_int, authority_public_key)
    signed_blinded_message_int = sign_blinded_message(blinded_message_int, authority_private_key)
    unblinded_signature_int = unblind_signature(signed_blinded_message_int, r, authority_public_key)
    if not verify_blind_signature(message_hash_int, unblinded_signature_int, authority_public_key):
        return jsonify({'status': 'error', 'message': 'Error interno al generar la firma ciega.'}), 500

    try:
        new_token = BlindSignatureToken(
            user_id=current_user.id,
            message_hash=message_hash_str,
            signature_token=str(unblinded_signature_int),
            is_used=False
        )
        db.session.add(new_token)
        db.session.commit()

        return jsonify({
            'status': 'success',
            'message': 'Token de firma ciega generado exitosamente.',
            'signature_token': str(unblinded_signature_int),
            'vote_option': vote_option
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'status': 'error',
            'message': f'Error al generar el token: {str(e)}'
        }), 500

@app.route("/submit_vote", methods=['POST'])
@login_required
def submit_vote():
    if current_user.user_type != 'conventional':
        flash('Solo los usuarios convencionales pueden emitir votos.', 'danger')
        return jsonify({'status': 'error', 'message': 'Acceso no autorizado.'}), 403

    data = request.get_json()
    vote_option = data.get('vote_option')
    signature_token_str = data.get('signature_token')
    private_key_password = data.get('private_key_password') 
    user_public_key_pem = data.get('user_public_key_pem')

    if not all([vote_option, signature_token_str, private_key_password, user_public_key_pem]):
        return jsonify({'status': 'error', 'message': 'Faltan datos para enviar el voto.'}), 400

    try:
        signature_token_int = int(signature_token_str)
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Formato de token de firma inválido.'}), 400


    message_hash_int = hash_message_to_int(vote_option)
    message_hash_str = str(message_hash_int)


    token = BlindSignatureToken.query.filter_by(user_id=current_user.id, message_hash=message_hash_str).first()
    if not token:
        return jsonify({'status': 'error', 'message': 'No se encontró un token de firma ciega para esta opción de voto.'}), 403
    if token.is_used:
        return jsonify({'status': 'error', 'message': 'Este token de firma ciega ya ha sido utilizado para votar.'}), 403


    if not verify_blind_signature(message_hash_int, signature_token_int, authority_public_key):
        return jsonify({'status': 'error', 'message': 'El token de firma ciega es inválido.'}), 403


    decrypted_private_key_pem = decrypt_private_key(current_user.private_key_encrypted, private_key_password)
    if not decrypted_private_key_pem:
        return jsonify({'status': 'error', 'message': 'Contraseña de clave privada incorrecta.'}), 401


    message_to_sign_by_user = f"{vote_option}-{signature_token_str}"
    final_user_signature = sign_message(decrypted_private_key_pem, message_to_sign_by_user, private_key_password)


    if not verify_signature(user_public_key_pem, message_to_sign_by_user, final_user_signature):
        return jsonify({'status': 'error', 'message': 'Error al verificar la firma del voto con la clave pública del usuario.'}), 500


    new_vote = Vote(user_id=current_user.id,
                    vote_option=vote_option,
                    signature=final_user_signature,
                    timestamp=datetime.utcnow())
    db.session.add(new_vote)

    token.is_used = True
    db.session.commit()

    flash('¡Tu voto ha sido registrado exitosamente!', 'success')
    return jsonify({'status': 'success', 'message': 'Voto registrado exitosamente.'}), 200

@app.route("/download_public_key/<int:user_id>")
@login_required
def download_public_key(user_id):
    if current_user.id != user_id or current_user.user_type != 'conventional':
        flash('No tienes permiso para descargar esta clave.', 'danger')
        return redirect(url_for('home'))

    user = User.query.get_or_404(user_id)
    if not user.public_key:
        flash('Este usuario no tiene una clave pública asignada.', 'danger')
        return redirect(url_for('dashboard'))

    key_file = io.BytesIO(user.public_key.encode('utf-8'))
    filename = f"{user.username}_public.pem"

    return send_file(key_file,
                     mimetype='application/x-pem-file',
                     as_attachment=True,
                     download_name=filename)

@app.route("/get_vote_options")
@login_required
def get_vote_options():
    return jsonify(AVAILABLE_VOTE_OPTIONS)
```

- **Rutas Básicas**: `/` y `/home` muestran la página de inicio.
- **Autenticación**:
  - `/register`: Maneja el registro de usuarios, incluyendo la generación de llaves RSA y la encriptación de la clave privada para usuarios convencionales.
  - `/login`: Procesa el inicio de sesión, verificando credenciales y autenticando al usuario con Flask-Login.
  - `/logout`: Cierra la sesión del usuario.
- **Dashboards**:
  - `/dashboard`: Una ruta protegida (@login_required) que redirige a los usuarios a su panel específico (convencional o administrador).
  - El panel de administrador (admin_dashboard.html) muestra estadísticas de votación agregadas.
  - El panel de usuario (user_dashboard.html) permite votar y muestra los votos y tokens pendientes del usuario.
- **Proceso de Votación**:
  - `/request_blind_signature_token` (POST): Permite a los usuarios convencionales solicitar un token de firma ciega para una opción de voto. El servidor realiza el cegado, la firma y el descegado internamente, devolviendo la firma descegada (token) al cliente. Se valida la opción de voto y se previene la solicitud de tokens duplicados.
  - `/submit_vote` (POST): Recibe el voto final, el token de firma ciega y la contraseña de la clave privada del usuario. Desencripta la clave privada del usuario, firma el voto final con ella, verifica la firma ciega del token y la firma del usuario con su clave pública. Marca el token como usado y guarda el voto.
- **Descarga de Clave Pública**: `/download_public_key/<int:user_id>` permite a un usuario descargar su propia clave pública.
- **Opciones de Voto**: `/get_vote_options` devuelve la lista de opciones de voto disponibles.

---

## 6. Implementación Detallada del Frontend

El frontend se construyó con HTML para la estructura, CSS para el estilo y JavaScript para la interactividad.

### 6.1. templates/base.html - Plantilla Base

```html
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Enlace a nuestro archivo CSS -->
    <link rel="stylesheet" type="text/css" href="{{ url_for('static', filename='css/style.css') }}">
    {% if title %}
    <title>{{ title }} - Votación Digital</title>
    {% else %}
    <title>Votación Digital</title>
    {% endif %}
</head>

<body>
    <header class="new-header">
        <div class="header-container">
            <div class="header-flex-row">
                <!-- Logo -->
                <a href="{{ url_for('home') }}" class="header-logo-link">
                    <div class="header-logo-icon-bg">
                        <!-- SVG para 'Vote' -->
                        <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="header-logo-icon"
                             viewBox="0 0 16 16">
                            <path fill-rule="evenodd"
                                d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7 7 0 0 0 1.048-.625 11.8 11.8 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.263 63 63 0 0 0-2.887-.87C9.843.266 8.69 0 8 0m0 5a1.5 1.5 0 0 1 .5 2.915l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99A1.5 1.5 0 0 1 8 5" />
                        </svg>
                    </div>
                    <span class="header-logo-text">VotoSeguro</span>
                </a>

                <!-- Navegación de Escritorio -->
                <nav class="header-nav-desktop">
                    <a href="{{ url_for('home') }}" class="header-nav-link">
                        <!-- SVG para 'Home' -->
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
                            <polyline points="9 22 9 12 15 12 15 22" />
                        </svg>
                        <span>Inicio</span>
                    </a>
                    {% if current_user.is_authenticated %}
                    <a href="{{ url_for('dashboard') }}" class="header-nav-link">
                        <!-- SVG para 'Vote' (Dashboard) -->
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                             class="bi bi-lock" viewBox="0 0 16 16">
                            <path fill-rule="evenodd"
                                d="M8 0a4 4 0 0 1 4 4v2.05a2.5 2.5 0 0 1 2 2.45v5a2.5 2.5 0 0 1-2.5 2.5h-7A2.5 2.5 0 0 1 2 13.5v-5a2.5 2.5 0 0 1 2-2.45V4a4 4 0 0 1 4-4M4.5 7A1.5 1.5 0 0 0 3 8.5v5A1.5 1.5 0 0 0 4.5 15h7a1.5 1.5 0 0 0 1.5-1.5v-5A1.5 1.5 0 0 0 11.5 7zM8 1a3 3 0 0 0-3 3v2h6V4a3 3 0 0 0-3-3" />
                        </svg>
                        <span>Dashboard</span>
                    </a>

                    {% endif %}
                </nav>

                <!-- Menú de Usuario (Escritorio) -->
                <div class="header-user-menu-desktop">
                    {% if current_user.is_authenticated %}
                    <div class="user-info-text">
                        <span class="user-name">{{ current_user.full_name or current_user.email }}</span>
                        {# {% if current_user.role == 'admin' %}
                        <span class="user-role-admin">Administrador</span>
                        {% endif %} #}
                    </div>
                    <a href="{{ url_for('logout') }}" class="header-user-button-logout">
                        <!-- SVG para 'LogOut' -->
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
                            <polyline points="16 17 21 12 16 7" />
                            <line x1="21" y1="12" x2="9" y2="12" />
                        </svg>
                        <span>Salir</span>
                    </a>
                    {% else %}
                    <a href="{{ url_for('login') }}" class="header-user-button-login">
                        Acceder
                    </a>
                    <a href="{{ url_for('register') }}" class="header-user-button-register">
                        Registrarse
                    </a>
                    {% endif %}
                </div>
            </div>
        </div>
    </header>
    <main>
        {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
        <ul class="flashes">
            {% for category, message in messages %}
            <li class="{{ category }}">{{ message }}</li>
            {% endfor %}
        </ul>
        {% endif %}
        {% endwith %}
        {% block content %}{% endblock %}
    </main>
    <footer>
        <div class="footer-container">
            <div class="footer-content">
                <p class="footer-text-main">© 2025 VotoSeguro - Sistema de Votación Digital</p>
                <p class="footer-text-secondary">
                    Tu voto es privado y seguro
                </p>
            </div>
        </div>
    </footer>
    <!-- Enlace a nuestro archivo JavaScript -->
    <script src="{{ url_for('static', filename='js/main.js') }}"></script>
</body>

</html>
```

- Define la estructura común para todas las páginas.
- Incluye enlaces a CSS y JavaScript.
- Muestra un menú de navegación dinámico basado en el estado de autenticación del usuario.
- Contiene un bloque para mostrar mensajes flash (get_flashed_messages).
- Define un bloque content donde las plantillas hijas insertarán su contenido específico.

### 6.2. templates/home.html - Página de Inicio

```html
{% extends "base.html" %}

{% block content %}
<div class="home-page-content">

    <section class="home-hero">
        <div class="home-hero-bg"></div>
        <div class="home-hero-overlay"></div>

        <div class="home-container home-hero-content">
            <div class="hero-text-animation">
                <div class="hero-badge">
                    <!-- SVG para 'Vote' -->
                    <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" class="header-logo-icon"
                        viewBox="0 0 16 16">
                        <path fill-rule="evenodd"
                            d="M8 0c-.69 0-1.843.265-2.928.56-1.11.3-2.229.655-2.887.87a1.54 1.54 0 0 0-1.044 1.262c-.596 4.477.787 7.795 2.465 9.99a11.8 11.8 0 0 0 2.517 2.453c.386.273.744.482 1.048.625.28.132.581.24.829.24s.548-.108.829-.24a7 7 0 0 0 1.048-.625 11.8 11.8 0 0 0 2.517-2.453c1.678-2.195 3.061-5.513 2.465-9.99a1.54 1.54 0 0 0-1.044-1.263 63 63 0 0 0-2.887-.87C9.843.266 8.69 0 8 0m0 5a1.5 1.5 0 0 1 .5 2.915l.385 1.99a.5.5 0 0 1-.491.595h-.788a.5.5 0 0 1-.49-.595l.384-1.99A1.5 1.5 0 0 1 8 5" />
                    </svg>
                    <span>Sistema de Votación Electrónica</span>
                </div>

                <h1 class="home-hero-title">
                    Tu Voz Cuenta,<br />
                    <span class="home-hero-subtitle-gradient">Tu Voto Importa</span>
                </h1>

                <p class="home-hero-description">
                    Participa de manera segura y transparente en el proceso democrático.
                    Sistema moderno de votación electrónica.
                </p>

                {% if current_user.is_authenticated %}
                <p class="hero-welcome-user">
                    Bienvenido/a, <span style="font-weight: 600;">{{ current_user.full_name or current_user.email
                        }}</span>
                </p>
                {% endif %}
            </div>
        </div>

        <!-- Divisor de Ola -->
        <div class="hero-wave-divider">
            <svg viewBox="0 0 1440 120" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path
                    d="M0 120L60 105C120 90 240 60 360 45C480 30 600 30 720 37.5C840 45 960 60 1080 67.5C1200 75 1320 75 1380 75L1440 75V120H1380C1320 120 1200 120 1080 120C960 120 840 120 720 120C600 120 480 120 360 120C240 120 120 120 60 120H0Z"
                    fill="rgb(248, 250, 252)" />
            </svg>
        </div>
    </section>

    <!-- Sección de Características -->
    <section class="home-features">
        <div class="home-container">
            <div class="home-section-title">
                <h2 class="home-section-h2">¿Por qué VotoSeguro?</h2>
                <p class="home-section-p">
                    Tecnología de punta para garantizar un proceso electoral justo y transparente
                </p>
            </div>

            <div class="home-features-grid">
                <!-- Característica 1 -->
                <div class="home-feature-card">
                    <div class="card-icon-wrapper bg-blue">
                        <!-- SVG para 'Shield' -->
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                            class="text-blue">
                            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                        </svg>
                    </div>
                    <h3 class="card-title">Seguro y Confiable</h3>
                    <p class="card-description">Tu voto está protegido con tecnología de encriptación avanzada</p>
                </div>
                <!-- Característica 3 -->
                <div class="home-feature-card">
                    <div class="card-icon-wrapper bg-purple">
                        <!-- SVG para 'CheckCircle' -->
                        <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                            class="text-purple">
                            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                            <path d="m9 11 3 3L22 4" />
                        </svg>
                    </div>
                    <h3 class="card-title">Un Voto por Persona</h3>
                    <p class="card-description">Sistema que previene votos duplicados automáticamente</p>
                </div>
            </div>
        </div>
    </section>

    <!-- Sección CTA (Call to Action) -->
    <section class="home-cta">
        <div class="home-container" style="max-width: 56rem; text-align: center;">
            <div class="cta-animation">
                <h2 class="home-section-h2" style="color: white;">¿Listo para ejercer tu derecho al voto?</h2>
                <p class="home-section-p" style="color: #dbeafe; margin-bottom: 2rem;">
                    El proceso es simple, seguro y toma menos de un minuto
                </p>
                {% if not current_user.is_authenticated %}
                <a href="{{ url_for('login') }}" class="btn-home btn-home-primary">
                    Comenzar Ahora
                    <!-- SVG para 'ArrowRight' -->
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none"
                        stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <path d="M5 12h14" />
                        <path d="m12 5 7 7-7 7" />
                    </svg>
                </a>
                {% endif %}
            </div>
        </div>
    </section>

</div>
{% endblock content %}
```

- Extiende base.html y proporciona un mensaje de bienvenida.

### 6.3. templates/register.html - Formulario de Registro

```html
{% extends "base.html" %}
{% block content %}
<div class="auth-form-wrapper">

    <!-- Encabezado del formulario con el logo -->
    <div class="auth-header">
        <div class="header-logo-icon-bg" style="width: 3rem; height: 3rem;">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="header-logo-icon"
                style="width: 1.75rem; height: 1.75rem;" viewBox="0 0 16 16">
                <path
                    d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6m-5.784 6A2.24 2.24 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.3 6.3 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1zM4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5" />
            </svg>
        </div>
        <h2>Crea una Cuenta para ingresar</h2>
    </div>

    <form method="POST" action="{{ url_for('register') }}" class="auth-form">
        {{ form.hidden_tag() }}

        <div class="form-group">
            {{ form.username.label(class="form-label") }}
            {{ form.username(class="form-control", placeholder="Elige un nombre de usuario") }}
            {% if form.username.errors %}
            <ul class="errors">
                {% for error in form.username.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group">
            {{ form.password.label(class="form-label") }}
            {{ form.password(class="form-control", placeholder="Crea una contraseña segura") }}
            {% if form.password.errors %}
            <ul class="errors">
                {% for error in form.password.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group">
            {{ form.confirm_password.label(class="form-label") }}
            {{ form.confirm_password(class="form-control", placeholder="Confirma tu contraseña") }}
            {% if form.confirm_password.errors %}
            <ul class="errors">
                {% for error in form.confirm_password.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group">
            {{ form.user_type.label(class="form-label") }}
            {{ form.user_type(class="form-control") }}
            {% if form.user_type.errors %}
            <ul class="errors">
                {% for error in form.user_type.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group">
            {{ form.submit(class="btn-dash-primary w-100") }}
        </div>
    </form>
    <!-- Link de Login actualizado -->
    <div class="register-link">
        <p>¿Ya tienes una cuenta? <a href="{{ url_for('login') }}">Inicia Sesión</a></p>
    </div>
</div>
{% endblock content %}
```

- Renderiza el formulario de registro utilizando Jinja2 para mostrar los campos y los errores de validación de Flask-WTF.

### 6.4. templates/login.html - Formulario de Inicio de Sesión

```html
{% extends "base.html" %}
{% block content %}

<div class="auth-form-wrapper">
    <!-- Encabezado del formulario con el logo -->
    <div class="auth-header">
        <div class="header-logo-icon-bg" style="width: 3rem; height: 3rem;">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="header-logo-icon"
                style="width: 1.75rem; height: 1.75rem;" viewBox="0 0 16 16">
                <path
                    d="M7 14s-1 0-1-1 1-4 5-4 5 3 5 4-1 1-1 1zm4-6a3 3 0 1 0 0-6 3 3 0 0 0 0 6m-5.784 6A2.24 2.24 0 0 1 5 13c0-1.355.68-2.75 1.936-3.72A6.3 6.3 0 0 0 5 9c-4 0-5 3-5 4s1 1 1 1zM4.5 8a2.5 2.5 0 1 0 0-5 2.5 2.5 0 0 0 0 5" />
            </svg>

        </div>
        <h2>Inicia Sesión</h2>
    </div>

    <form method="POST" action="{{ url_for('login') }}" class="auth-form">
        {{ form.hidden_tag() }}

        <div class="form-group">
            {{ form.username.label(class="form-label") }}
            {{ form.username(class="form-control", placeholder="Tu nombre de usuario") }}
            {% if form.username.errors %}
            <ul class="errors">
                {% for error in form.username.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group">
            {{ form.password.label(class="form-label") }}
            {{ form.password(class="form-control", placeholder="Tu contraseña") }}
            {% if form.password.errors %}
            <ul class="errors">
                {% for error in form.password.errors %}
                <li>{{ error }}</li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>

        <div class="form-group-remember">
            {# Asumiendo que tu form.remember tiene un id autogenerado, usamos 'for' #}
            {{ form.remember(id="remember-me") }}
            {{ form.remember.label(for="remember-me") }}
        </div>

        <div class="form-group">
            {{ form.submit(class="btn-dash-primary w-100") }}
        </div>
    </form>

    <!-- Link de Registro -->
    <div class="register-link">
        <p>¿Necesitas una cuenta? <a href="{{ url_for('register') }}">Regístrate Aquí</a></p>
    </div>
</div>
{% endblock content %}
```

- Renderiza el formulario de inicio de sesión, similar al de registro.

### 6.5. templates/user_dashboard.html - Panel de Usuario Convencional

```html
{% extends "base.html" %}
{% block content %}

<!-- Título Principal del Dashboard -->
<h2 class="dashboard-main-title">Panel de Votación</h2>
<p class="dashboard-subtitle">Bienvenido, {{ current_user.username }}! Aquí puedes gestionar tu participación.</p>

<div class="dashboard-grid">

    <!-- Tarjeta Principal: Realizar Votación -->
    <div class="dashboard-card vote-card">
        <h3>Realizar Votación</h3>
        <p>Sigue los pasos para emitir tu voto de forma segura y anónima.</p>

        <form id="vote-form" class="vote-form-content">
            <div class="form-group">
                <label for="vote_option">1. Selecciona tu opción de voto:</label>
                <select id="vote_option" name="vote_option" class="form-control">
                    {% for option in available_options %}
                    <option value="{{ option }}">{{ option }}</option>
                    {% endfor %}
                </select>
            </div>
            <div class="form-group">
                <label for="private_key_password">2. Contraseña de tu clave privada:</label>
                <input type="password" id="private_key_password" name="private_key_password" class="form-control"
                    required>
                <small>Es la misma contraseña con la que te registraste, usada para firmar tu voto.</small>
            </div>
            <div class="form-group">
                <label for="user_public_key_file">3. Sube tu llave pública (.pem):</label>
                <!-- Wrapper de input de archivo personalizado -->
                <div class="file-input-wrapper">
                    <input type="file" id="user_public_key_file" accept=".pem" class="file-input-hidden" required>
                    <label for="user_public_key_file" class="file-input-label">
                        <span id="file-name-display">Seleccionar archivo...</span>
                    </label>
                </div>
                <small>Necesaria para verificar tu firma final.</small>
            </div>

            <!-- Mensaje de Estado -->
            <div id="status-message" class="status-box" style="display: none;"></div>

            <!-- Botones de Acción -->
            <div class="vote-buttons-container">
                <button type="button" id="request-token-btn" class="btn-dash-primary">1. Solicitar Token</button>
                <button type="button" id="submit-vote-btn" class="btn-dash-primary" disabled>2. Enviar Voto
                    Final</button>
            </div>
        </form>
    </div>

    <!-- Tarjeta Secundaria: Información de Usuario -->
    <div class="dashboard-card info-card">
        <h3>Información de Usuario</h3>
        <div class="info-grid">
            <span>Usuario:</span>
            <strong>{{ current_user.username }}</strong>

            <span>ID de Usuario:</span>
            <strong>{{ current_user.id }}</strong>

            <span>Tipo de Usuario:</span>
            <strong>{{ current_user.user_type }}</strong>
        </div>
        <hr class="card-divider">
        <h4>Gestión de Clave</h4>
        <p>Tu clave pública fue generada y almacenada. Puedes descargarla si la perdiste.</p>
        <a href="{{ url_for('download_public_key', user_id=current_user.id) }}" class="btn-dash-secondary">
            <!-- SVG para 'Descargar' -->
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none"
                stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
                <polyline points="7 10 12 15 17 10" />
                <line x1="12" y1="15" x2="12" y2="3" />
            </svg>
            Descargar mi Clave Pública
        </a>
    </div>

    <!-- Tarjeta Ancha: Mis Votaciones Realizadas -->
    <div class="dashboard-card full-width-card">
        <h3>Mis Votaciones Realizadas</h3>
        {% if user_votes %}
        <div class="table-wrapper">
            <table class="modern-table">
                <thead>
                    <tr>
                        <th>Opción Votada</th>
                        <th>Fecha/Hora</th>
                        <th>Firma del Voto (extracto)</th>
                    </tr>
                </thead>
                <tbody>
                    {% for vote in user_votes %}
                    <tr>
                        <td data-label="Opción">{{ vote.vote_option }}</td>
                        <td data-label="Fecha">{{ vote.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                        <td data-label="Firma" class="signature-cell">{{ vote.signature[:50] }}...</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p>Aún no has emitido ningún voto.</p>
        {% endif %}
    </div>

    <!-- Tarjeta Ancha: Tokens Pendientes -->
    <div class="dashboard-card full-width-card">
        <h3>Tokens de Firma Ciega Pendientes</h3>
        {% if pending_tokens %}
        <div class="table-wrapper">
            <table class="modern-table">
                <thead>
                    <tr>
                        <th>Hash del Mensaje</th>
                        <th>Token (extracto)</th>
                        <th>Estado</th>
                    </tr>
                </thead>
                <tbody>
                    {% for token in pending_tokens %}
                    <tr>
                        <td data-label="Hash" class="signature-cell">{{ token.message_hash[:20] }}...</td>
                        <td data-label="Token" class="signature-cell">{{ token.signature_token[:20] }}...</td>
                        <td data-label="Estado">Pendiente (no usado)</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p>No tienes tokens de firma ciega pendientes.</p>
        {% endif %}
    </div>

</div>


<script>
    let signatureToken = null;
    let userPublicKey = null;

    document.getElementById('user_public_key_file').addEventListener('change', function () {
        const fileName = this.files[0] ? this.files[0].name : 'Seleccionar archivo...';
        document.getElementById('file-name-display').textContent = fileName;
    });

    // Función para leer el archivo de clave pública
    function readPublicKeyFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = (e) => reject(e);
            reader.readAsText(file);
        });
    }

    // Validar formato PEM básico
    function validatePEM(pemContent) {
        return pemContent.includes('-----BEGIN PUBLIC KEY-----') &&
            pemContent.includes('-----END PUBLIC KEY-----');
    }

    // --- LISTENER BOTÓN 1: Solicitar Token ---
    document.getElementById('request-token-btn').addEventListener('click', async () => {
        const voteOption = document.getElementById('vote_option').value;
        const statusMessage = document.getElementById('status-message');
        const publicKeyFile = document.getElementById('user_public_key_file').files[0];

        // Mostrar el cuadro de estado
        statusMessage.style.display = 'block';

        if (!publicKeyFile) {
            statusMessage.textContent = 'Por favor, selecciona tu archivo de clave pública (.pem)';
            statusMessage.className = 'status-box error';
            return;
        }

        let userPublicKeyPem;
        try {
            userPublicKeyPem = await readPublicKeyFile(publicKeyFile);
            if (!validatePEM(userPublicKeyPem)) {
                statusMessage.textContent = 'El archivo no parece ser una clave pública válida en formato PEM';
                statusMessage.className = 'status-box error';
                return;
            }
        } catch (error) {
            statusMessage.textContent = 'Error al leer el archivo de clave pública';
            statusMessage.className = 'status-box error';
            return;
        }

        statusMessage.textContent = 'Solicitando token de firma ciega...';
        statusMessage.className = 'status-box info';
        document.getElementById('request-token-btn').disabled = true;
        document.getElementById('submit-vote-btn').disabled = true;

        try {
            const response = await fetch('/request_blind_signature_token', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ vote_option: voteOption })
            });
            const data = await response.json();

            if (data.status === 'success') {
                signatureToken = data.signature_token; // Almacenamos el token
                statusMessage.textContent = data.message + ' Ahora puedes enviar tu voto.';
                statusMessage.className = 'status-box success';
                document.getElementById('submit-vote-btn').disabled = false; // Habilitamos el segundo botón
            } else {
                statusMessage.textContent = 'Error al solicitar token: ' + data.message;
                statusMessage.className = 'status-box error';
            }
        } catch (error) {
            statusMessage.textContent = 'Error de conexión: ' + error.message;
            statusMessage.className = 'status-box error';
        } finally {
            document.getElementById('request-token-btn').disabled = false;
        }
    });

    // --- LISTENER BOTÓN 2: Enviar Voto ---
    document.getElementById('submit-vote-btn').addEventListener('click', async () => {
        const statusMessage = document.getElementById('status-message');

        // Asegurarse de que el cuadro de estado sea visible
        statusMessage.style.display = 'block';

        if (!signatureToken) {
            statusMessage.textContent = 'Primero debes solicitar un token de firma ciega.';
            statusMessage.className = 'status-box error';
            return;
        }

        const voteOption = document.getElementById('vote_option').value;
        const privateKeyPassword = document.getElementById('private_key_password').value;
        const userPublicKeyFile = document.getElementById('user_public_key_file').files[0];

        if (!privateKeyPassword) {
            statusMessage.textContent = 'Por favor, introduce la contraseña de tu clave privada.';
            statusMessage.className = 'status-box error';
            return;
        }

        if (!userPublicKeyFile) {
            statusMessage.textContent = 'Por favor, sube tu llave pública para verificar la firma.';
            statusMessage.className = 'status-box error';
            return;
        }

        statusMessage.textContent = 'Enviando voto final...';
        statusMessage.className = 'status-box info';
        document.getElementById('request-token-btn').disabled = true;
        document.getElementById('submit-vote-btn').disabled = true;

        let userPublicKeyPem;
        try {
            userPublicKeyPem = await readPublicKeyFile(userPublicKeyFile);
            if (!validatePEM(userPublicKeyPem)) {
                throw new Error('El archivo no parece ser una clave pública válida en formato PEM');
            }
        } catch (error) {
            statusMessage.textContent = 'Error al leer la clave pública: ' + error.message;
            statusMessage.className = 'status-box error';
            document.getElementById('request-token-btn').disabled = false;
            document.getElementById('submit-vote-btn').disabled = false;
            return;
        }

        // Hacemos una llamada fetch con TODOS los datos
        try {
            const response = await fetch('/submit_vote', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    vote_option: voteOption,
                    signature_token: signatureToken,
                    private_key_password: privateKeyPassword,
                    user_public_key_pem: userPublicKeyPem // Enviamos el contenido PEM
                })
            });

            const data = await response.json();

            if (data.status === 'success') {
                statusMessage.textContent = data.message;
                statusMessage.className = 'status-box success';
                signatureToken = null; // Limpiar el token después de usarlo
                // Recargar la página para ver los votos actualizados
                setTimeout(() => {
                    window.location.reload();
                }, 1500); // Recargar después de 1.5 segundos
            } else {
                statusMessage.textContent = 'Error al enviar voto: ' + data.message;
                statusMessage.className = 'status-box error';
            }
        } catch (error) {
            statusMessage.textContent = 'Error de conexión: ' + error.message;
            statusMessage.className = 'status-box error';
        } finally {
            if (statusMessage.className.includes('error')) {
                // Solo re-habilitar si hubo un error, si fue exitoso, recargará
                document.getElementById('request-token-btn').disabled = false;
                document.getElementById('submit-vote-btn').disabled = false;
            }
        }
    });
</script>

{% endblock content %}

```

- Proporciona la interfaz principal para usuarios convencionales.
- Permite seleccionar una opción de voto descargar la llave publica, solicitar un token de firma ciega y enviar el voto final.
- Muestra las votaciones ya realizadas por el usuario y los tokens de firma ciega pendientes.
- El JavaScript embebido maneja el flujo de votación asíncrono, interactuando con las rutas /request_blind_signature_token y /submit_vote.

### 6.6. templates/admin_dashboard.html - Panel de Administrador

```html
{% extends "base.html" %}
{% block content %}

<!-- Título Principal del Dashboard -->
<h2 class="dashboard-main-title">Panel de Administrador</h2>
<p class="dashboard-subtitle">¡Bienvenido, {{ current_user.username }}! Aquí puedes ver las estadísticas de las
    votaciones.</p>

<div class="dashboard-grid">

    <!-- Tarjeta Principal: Estadísticas de Votación -->
    <div class="dashboard-card">
        <h3>Estadísticas de Votación</h3>
        {% if total_votes > 0 %}
        <p>Total de votos emitidos: <strong>{{ total_votes }}</strong></p>

        <div class="table-wrapper">
            <table class="modern-table">
                <thead>
                    <tr>
                        <th>Opción de Voto</th>
                        <th>Número de Votos</th>
                        <th>Porcentaje</th>
                    </tr>
                </thead>
                <tbody>
                    {% for stat in statistics %}
                    <tr>
                        <td data-label="Opción">{{ stat.option }}</td>
                        <td data-label="Votos">{{ stat.count }}</td>
                        <td data-label="Porcentaje">{{ ((stat.count / total_votes) * 100) | round(2) }}%</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% else %}
        <p>Aún no se han emitido votos.</p>
        {% endif %}
    </div>

    <!-- Tarjeta Secundaria: Información de Administrador -->
    <div class="dashboard-card info-card">
        <h3>Información de Administrador</h3>
        <div class="info-grid">
            <span>Usuario:</span>
            <strong>{{ current_user.username }}</strong>

            <span>ID de Usuario:</span>
            <strong>{{ current_user.id }}</strong>

            <span>Tipo de Usuario:</span>
            <strong>{{ current_user.user_type }}</strong>
        </div>

    </div>

    {% if statistics and total_votes > 0 %}
    <div class="dashboard-card winning-card">
        <h3>🏆 Resultados Parciales</h3>
        <div class="winner-info">
            <span class="winner-label">Candidato a la delantera:</span>
            <strong class="winner-name">{{ statistics[0].option }}</strong>
            <span class="winner-votes">{{ statistics[0].count }} Votos</span>

            <!-- Barra de Progreso del Ganador -->
            <div class="winner-percentage-bar">
                <div class="winner-percentage-fill animated-fill"
                    style="--percentage-width: {{ ((statistics[0].count / total_votes) * 100) | round(2) }}%; width: var(--percentage-width);">

                    {{ ((statistics[0].count / total_votes) * 100) | round(2) }}%
                </div>
            </div>
        </div>

        <!-- Mostrar el segundo lugar si existe -->
        {% if statistics[1] %}
        <div class="runner-up-info">
            <span class="runner-up-label">Segundo lugar:</span>
            <div>
                <strong class="runner-up-name">{{ statistics[1].option }}</strong>
                <span class="runner-up-votes">({{ statistics[1].count }} Votos)</span>
            </div>
        </div>
        {% endif %}
    </div>
    {% endif %}

</div>

{% endblock content %}
```

- Muestra un resumen de las estadísticas de votación, incluyendo el total de votos y el desglose por opción, con porcentajes.

### 6.7. static/css/style.css - Estilos CSS

```css
@keyframes gradientBG {
    0% {
        background-position: 0% 50%;
    }

    50% {
        background-position: 100% 50%;
    }

    100% {
        background-position: 0% 50%;
    }
}

@keyframes slideDown {
    from {
        transform: translateY(-100%);
        opacity: 0;
    }

    to {
        transform: translateY(0);
        opacity: 1;
    }
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(20px);
    }

    to {
        opacity: 1;
        transform: translateY(0);
    }
}

@keyframes slideInRight {
    from {
        transform: translateX(100%);
        opacity: 0;
    }

    to {
        transform: translateX(0);
        opacity: 1;
    }
}

body {
    font-family: Arial, sans-serif;
    margin: 0;
    padding: 0;
    background-color: #f1f5f9;
    color: #333;
    line-height: 1.6;
    padding-top: 4rem;
    /* Altura del new-header */
    box-sizing: border-box;
    display: flex;
    flex-direction: column;
    min-height: 100vh;
}

/* Estilo de 'main' por defecto (contenedor blanco centrado) */
main {
    padding: 25px;
    max-width: 800px;
    margin: 30px auto;
    background-color: rgba(255, 255, 255, 0.95);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
    border-radius: 12px;
    animation: fadeIn 0.6s ease-out forwards;
    transition: transform 0.3s ease, box-shadow 0.3s ease;
    flex-grow: 1;
    display: flex;
    flex-direction: column;
}

main:hover {
    transform: translateY(-5px);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.2);
}

.form-group {
    margin-bottom: 20px;
}

.form-group label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: #444;
}

.form-control {
    width: 100%;
    padding: 12px;
    border: 1px solid #ccc;
    border-radius: 6px;
    box-sizing: border-box;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
}

.form-control:focus {
    border-color: #007bff;
    box-shadow: 0 0 10px rgba(0, 123, 255, 0.3);
    outline: none;
}

.form-group-remember {
    display: flex;
    align-items: center;
    margin-bottom: 25px;
    font-size: 14px;
    color: #555;
}

.form-group-remember input[type="checkbox"] {
    margin-right: 10px;
    accent-color: #007bff;
}

.form-container .register-link {
    text-align: center;
    margin-top: 25px;
    font-size: 14px;
    color: #555;
}

.form-container .register-link a {
    color: #007bff;
    text-decoration: none;
    font-weight: bold;
    transition: all 0.3s ease;
}

.form-container .register-link a:hover {
    color: #0056b3;
    text-decoration: underline;
}

.flashes {
    list-style: none;
    padding: 0;
    margin: 0 0 20px 0;
}

.flashes li {
    padding: 15px;
    margin-bottom: 10px;
    border-radius: 8px;
    font-weight: bold;
    animation: slideInRight 0.5s ease-out;
}

.flashes .success {
    background-color: #d4edda;
    color: #155724;
    border: 1px solid #c3e6cb;
    box-shadow: 0 2px 5px rgba(21, 87, 36, 0.1);
}

.flashes .danger {
    background-color: #f8d7da;
    color: #721c24;
    border: 1px solid #f5c6cb;
    box-shadow: 0 2px 5px rgba(114, 28, 36, 0.1);
}

.flashes .info {
    background-color: #d1ecf1;
    color: #0c5460;
    border: 1px solid #bee5eb;
    box-shadow: 0 2px 5px rgba(12, 84, 96, 0.1);
}

.errors {
    color: #dc3545;
    font-size: 0.9em;
    list-style: none;
    padding-left: 0;
    margin-top: 5px;
}


/* --- 2. NUEVOS ESTILOS DE HEADER --- */
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border-width: 0;
}

.new-header {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 50;
    background-color: rgba(255, 255, 255, 0.8);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid #e2e8f0;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);
}

.header-container {
    max-width: 80rem;
    margin-left: auto;
    margin-right: auto;
    padding-left: 1rem;
    padding-right: 1rem;
}

@media (min-width: 640px) {
    .header-container {
        padding-left: 1.5rem;
        padding-right: 1.5rem;
    }
}

@media (min-width: 1024px) {
    .header-container {
        padding-left: 2rem;
        padding-right: 2rem;
    }
}

.header-flex-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    height: 4rem;
}

.header-logo-link {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-decoration: none;
    transition: all 0.3s ease;
}

.header-logo-icon-bg {
    width: 2.5rem;
    height: 2.5rem;
    background: linear-gradient(to bottom right, #2563eb, #3b82f6);
    border-radius: 0.75rem;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.1);
    transition: all 0.3s ease;
}

.header-logo-link:hover .header-logo-icon-bg {
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);
}

.header-logo-icon {
    width: 1.5rem;
    height: 1.5rem;
    color: white;
}

.header-logo-text {
    font-size: 1.25rem;
    font-weight: 700;
    background: linear-gradient(to right, #2563eb, #1e3a8a);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.header-nav-desktop {
    display: none;
}

@media (min-width: 768px) {
    .header-nav-desktop {
        display: flex;
        align-items: center;
        gap: 0.25rem;
    }
}

.header-nav-link {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    border-radius: 0.5rem;
    transition: all 0.2s ease;
    text-decoration: none;
    color: #475569;
    font-weight: 500;
}

.header-nav-link:hover {
    background-color: #f1f5f9;
}

.header-nav-link.active {
    background-color: #dbeafe;
    color: #2563eb;
    font-weight: 600;
}

.header-nav-link svg {
    width: 1rem;
    height: 1rem;
}

.header-user-menu-desktop {
    display: none;
}

@media (min-width: 768px) {
    .header-user-menu-desktop {
        display: flex;
        align-items: center;
        gap: 0.75rem;
    }
}

.user-info-text {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
}

.user-name {
    font-size: 0.875rem;
    font-weight: 600;
    color: #1e293b;
}

.user-role-admin {
    font-size: 0.75rem;
    font-weight: 600;
    color: #2563eb;
}

.header-user-button-logout {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    font-weight: 600;
    border: 1px solid #cbd5e1;
    color: #475569;
    background-color: white;
    border-radius: 0.375rem;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.2s ease;
}

.header-user-button-logout:hover {
    background-color: #f8fafc;
}

.header-user-button-logout svg {
    width: 1rem;
    height: 1rem;
}

.header-user-button-login {
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    font-weight: 600;
    border: 1px solid #2563eb;
    color: #2563eb;
    background-color: white;
    border-radius: 0.375rem;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.2s ease;
}

.header-user-button-login:hover {
    background-color: #f0f6ff;
}

.header-user-button-register {
    padding: 0.375rem 0.75rem;
    font-size: 0.875rem;
    font-weight: 600;
    border: 1px solid #2563eb;
    color: white;
    background-color: #2563eb;
    border-radius: 0.375rem;
    text-decoration: none;
    cursor: pointer;
    transition: all 0.2s ease;
}

.header-user-button-register:hover {
    background-color: #1d4ed8;
}

/* --- 3. NUEVOS ESTILOS PARA HOME --- */
main:has(.home-page-content) {
    max-width: none;
    margin: 0;
    padding: 0;
    background-color: transparent;
    box-shadow: none;
    border-radius: 0;
    animation: none;
    transition: none;
    display: flex;
    flex-direction: column;
}

main:has(.home-page-content):hover {
    transform: none;
    box-shadow: none;
}


.home-page-content {
    display: flex;
    flex-direction: column;
}

.home-container {
    max-width: 80rem;
    margin-left: auto;
    margin-right: auto;
    padding-left: 1rem;
    padding-right: 1rem;
}

@media (min-width: 640px) {
    .home-container {
        padding-left: 1.5rem;
        padding-right: 1.5rem;
    }
}

@media (min-width: 1024px) {
    .home-container {
        padding-left: 2rem;
        padding-right: 2rem;
    }
}

.home-hero {
    position: relative;
    overflow: hidden;
    background: linear-gradient(to bottom right, #2563eb, #3b82f6, #1e3a8a);
    color: white;
}

.home-hero-bg {
    position: absolute;
    inset: 0;
    background-image: url('https://images.unsplash.com/photo-1541872703-74c5e44368f9?w=1600');
    opacity: 0.1;
    background-size: cover;
    background-position: center;
}

.home-hero-overlay {
    position: absolute;
    inset: 0;
    background: linear-gradient(to bottom right, rgba(59, 130, 246, 0.9), rgba(30, 58, 138, 0.9));
}

.home-hero-content {
    position: relative;
    padding-top: 6rem;
    /* 96px */
    padding-bottom: 6rem;
    /* 96px */
    text-align: center;
}

@media (min-width: 640px) {
    .home-hero-content {
        padding-top: 8rem;
        /* 128px */
        padding-bottom: 8rem;
        /* 128px */
    }
}


.hero-text-animation {
    animation: fadeIn 0.6s ease-out forwards;
}

.hero-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    padding: 0.5rem 1rem;
    background-color: rgba(255, 255, 255, 0.1);
    backdrop-filter: blur(10px);
    border-radius: 9999px;
    margin-bottom: 1.5rem;
    font-size: 0.875rem;
    font-weight: 500;
}

.hero-badge svg {
    width: 1.25rem;
    height: 1.25rem;
}

.home-hero-title {
    font-size: 2.25rem;
    line-height: 2.5rem;
    font-weight: bold;
    margin-bottom: 1.5rem;
}

@media (min-width: 640px) {
    .home-hero-title {
        font-size: 3rem;
        line-height: 1;
    }
}

@media (min-width: 768px) {
    .home-hero-title {
        font-size: 3.75rem;
        line-height: 1;
    }
}

.home-hero-subtitle-gradient {
    background: linear-gradient(to right, #dbeafe, #ffffff);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.home-hero-description {
    font-size: 1.25rem;
    color: #dbeafe;
    margin-bottom: 2rem;
    max-width: 42rem;
    margin-left: auto;
    margin-right: auto;
}

/* Botones específicos de la Home  */
.btn-home {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    font-size: 1rem;
    font-weight: 600;
    padding: 0.75rem 1.5rem;
    border-radius: 9999px;
    text-decoration: none;
    transition: all 0.3s ease;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.btn-home svg {
    width: 1.25rem;
    height: 1.25rem;
}

.btn-home-primary {
    background-color: white;
    color: #3b82f6;
}

.btn-home-primary:hover {
    background-color: #f0f6ff;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
    transform: translateY(-2px);
}

.btn-home-secondary {
    border: 1px solid white;
    color: white;
}

.btn-home-secondary:hover {
    background-color: rgba(255, 255, 255, 0.1);
}

.hero-welcome-user {
    margin-top: 1.5rem;
    color: #dbeafe;
    animation: fadeIn 0.5s ease-out 0.3s forwards;
    opacity: 0;
}

/* Divisor de Ola */
.hero-wave-divider {
    position: absolute;
    bottom: -1px;
    left: 0;
    right: 0;
    width: 100%;
}

.hero-wave-divider svg {
    display: block;
    width: 100%;
    height: auto;
}

/* --- Estilos para 'home-features' y 'home-cta' --- */
.home-features {
    padding-top: 5rem;
    padding-bottom: 5rem;
    background-color: #ffffff;
}

.home-section-title {
    text-align: center;
    margin-bottom: 4rem;
    opacity: 0;
    transform: translateY(20px);
    animation: fadeIn 0.6s ease-out forwards;
}

.home-section-h2 {
    font-size: 2.25rem;
    font-weight: bold;
    color: #1e293b;
    margin-bottom: 1rem;
}

@media (min-width: 640px) {
    .home-section-h2 {
        font-size: 2.5rem;
    }
}

.home-section-p {
    font-size: 1.125rem;
    color: #475569;
    max-width: 42rem;
    margin-left: auto;
    margin-right: auto;
}

.home-features-grid {
    display: grid;
    gap: 2rem;
}

@media (min-width: 768px) {
    .home-features-grid {
        grid-template-columns: repeat(2, 1fr);
        max-width: 56rem;
        margin-left: auto;
        margin-right: auto;
    }
}

.home-feature-card {
    border: 2px solid #e2e8f0;
    background-color: white;
    border-radius: 0.75rem;
    text-align: center;
    padding: 2rem;
    transition: all 0.3s ease;
    opacity: 0;
    transform: translateY(20px);
    animation: fadeIn 0.6s ease-out forwards;
}

.home-features-grid>div:nth-child(2) {
    animation-delay: 0.1s;
}

.home-features-grid>div:nth-child(3) {
    animation-delay: 0.2s;
}

.home-feature-card:hover {
    transform: translateY(-0.25rem);
    box-shadow: 0 12px 30px rgba(0, 0, 0, 0.1);
}

.card-icon-wrapper {
    width: 4rem;
    height: 4rem;
    margin-left: auto;
    margin-right: auto;
    margin-bottom: 1.5rem;
    border-radius: 1rem;
    display: flex;
    align-items: center;
    justify-content: center;
}

.card-icon-wrapper.bg-blue {
    background: linear-gradient(to bottom right, #dbeafe, #bfdbfe);
}

.card-icon-wrapper.bg-purple {
    background: linear-gradient(to bottom right, #ede9fe, #ddd6fe);
}

.card-icon-wrapper svg.text-blue {
    color: #3b82f6;
}

.card-icon-wrapper svg.text-purple {
    color: #8b5cf6;
}

.card-title {
    font-size: 1.25rem;
    font-weight: bold;
    color: #1e293b;
    margin-bottom: 0.75rem;
}

.card-description {
    color: #475569;
}

.home-cta {
    padding-top: 5rem;
    padding-bottom: 5rem;
    background: linear-gradient(to bottom right, #1e293b, #1e3a8a);
    color: white;
}

.cta-animation {
    opacity: 0;
    transform: translateY(20px);
    animation: fadeIn 0.6s ease-out forwards;
}


/* --- 4. NUEVOS ESTILOS DE FOOTER --- */
footer {
    margin-top: auto;
    border-top: 1px solid #e2e8f0;
    background-color: #ffffff;
}

.footer-container {
    max-width: 80rem;
    margin-left: auto;
    margin-right: auto;
    padding: 2rem 1rem;
}

@media (min-width: 640px) {
    .footer-container {
        padding-left: 1.5rem;
        padding-right: 1.5rem;
    }
}

@media (min-width: 1024px) {
    .footer-container {
        padding-left: 2rem;
        padding-right: 2rem;
    }
}

.footer-content {
    text-align: center;
    color: #475569;
}

.footer-text-main {
    font-size: 0.875rem;
    margin: 0;
}

.footer-text-secondary {
    font-size: 0.75rem;
    margin-top: 0.25rem;
    color: #64748b;
    margin-bottom: 0;
}

/* --- 5. NUEVOS ESTILOS DEL DASHBOARD --- */

.dashboard-main-title {
    font-size: 1.75rem;
    font-weight: 700;
    color: #1e293b;
    /* slate-900 */
    margin-top: 0;
    margin-bottom: 0.25rem;
}

.dashboard-subtitle {
    font-size: 1rem;
    color: #64748b;
    /* slate-500 */
    margin-top: 0;
    margin-bottom: 2rem;
}

/* --- Diseño de Cuadrícula --- */
.dashboard-grid {
    display: grid;
    grid-template-columns: 1fr;
    gap: 1.5rem;
}

@media (min-width: 1024px) {
    .dashboard-grid {
        grid-template-columns: 2fr 1fr;
    }

    .full-width-card {
        /* Hacer que las tarjetas de tabla ocupen ambas columnas */
        grid-column: 1 / -1;
    }
}

/* --- Estilo de Tarjetas --- */
.dashboard-card {
    background-color: #ffffff;
    border-radius: 0.75rem;
    /* 12px */
    border: 1px solid #e2e8f0;
    /* slate-200 */
    padding: 1.5rem;
    /* 24px */
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.05), 0 2px 4px -2px rgba(0, 0, 0, 0.05);
}

.dashboard-card h3 {
    font-size: 1.25rem;
    /* 20px */
    font-weight: 600;
    color: #1e293b;
    margin-top: 0;
    margin-bottom: 1rem;
}

.dashboard-card p {
    font-size: 0.875rem;
    /* 14px */
    color: #475569;
    /* slate-600 */
}

.card-divider {
    border: 0;
    height: 1px;
    background-color: #e2e8f0;
    margin: 1.5rem 0;
}

/* --- Tarjeta de Votación Específica --- */
.vote-card {
    /* Color de fondo sutil para destacar */
    background-color: #f8fafc;
    /* slate-50 */
}

.vote-form-content {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.vote-buttons-container {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

@media (min-width: 768px) {
    .vote-buttons-container {
        flex-direction: row;
    }
}

/* --- Tarjeta de Información Específica --- */
.info-grid {
    display: grid;
    grid-template-columns: auto 1fr;
    gap: 0.75rem 1rem;
    font-size: 0.875rem;
}

.info-grid span {
    color: #64748b;
    /* slate-500 */
}

.info-grid strong {
    color: #334155;
    /* slate-700 */
    font-weight: 600;
    word-break: break-all;
}

/* --- Nuevos Estilos de Botones --- */
.btn-dash-primary,
.btn-dash-secondary {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
    padding: 0.625rem 1.25rem;
    /* 10px 20px */
    font-size: 0.875rem;
    /* 14px */
    font-weight: 600;
    border-radius: 0.375rem;
    /* 6px */
    text-decoration: none;
    cursor: pointer;
    transition: all 0.2s ease;
    border: 1px solid transparent;
    line-height: 1.25;
}

.btn-dash-primary {
    background-color: #2563eb;
    /* blue-600 */
    color: white;
    border-color: #2563eb;
}

.btn-dash-primary:hover {
    background-color: #1d4ed8;
    /* blue-700 */
    border-color: #1d4ed8;
}

.btn-dash-primary:disabled {
    background-color: #94a3b8;
    /* slate-400 */
    border-color: #94a3b8;
    cursor: not-allowed;
}

.btn-dash-secondary {
    background-color: white;
    color: #475569;
    /* slate-600 */
    border-color: #cbd5e1;
    /* slate-300 */
}

.btn-dash-secondary:hover {
    background-color: #f8fafc;
    /* slate-50 */
    border-color: #94a3b8;
    /* slate-400 */
}

.btn-dash-secondary svg {
    width: 1rem;
    height: 1rem;
}

/* --- Estilo de Input de Archivo --- */
.file-input-wrapper {
    position: relative;
    width: 100%;
}

.file-input-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    opacity: 0;
    overflow: hidden;
    z-index: -1;
}

.file-input-label {
    display: block;
    padding: 0.75rem 1rem;
    border: 1px solid #ccc;
    border-radius: 6px;
    background-color: white;
    cursor: pointer;
    transition: border-color 0.3s ease, box-shadow 0.3s ease;
    font-size: 0.875rem;
    color: #475569;
}

.file-input-hidden:focus+.file-input-label {
    border-color: #007bff;
    box-shadow: 0 0 10px rgba(0, 123, 255, 0.3);
    outline: none;
}

#file-name-display {
    display: block;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
}


/* --- Estilo de Mensaje de Estado --- */
.status-box {
    padding: 1rem;
    border-radius: 0.375rem;
    font-weight: 500;
    font-size: 0.875rem;
    margin: 0.5rem 0;
}

.status-box.info {
    background-color: #dbeafe;
    /* blue-100 */
    color: #1e40af;
    /* blue-800 */
    border: 1px solid #93c5fd;
    /* blue-300 */
}

.status-box.success {
    background-color: #dcfce7;
    /* green-100 */
    color: #14532d;
    /* green-900 */
    border: 1px solid #86efac;
    /* green-300 */
}

.status-box.error {
    background-color: #fee2e2;
    /* red-100 */
    color: #7f1d1d;
    /* red-900 */
    border: 1px solid #fca5a5;
    /* red-300 */
}

/* --- Estilo de Tabla Moderno --- */
.table-wrapper {
    width: 100%;
    overflow-x: auto;
}

.modern-table {
    width: 100%;
    border-collapse: collapse;
    margin-top: 1rem;
}

.modern-table th,
.modern-table td {
    padding: 0.75rem 1rem;
    /* 12px 16px */
    text-align: left;
    font-size: 0.875rem;
    border-bottom: 1px solid #e2e8f0;
    /* slate-200 */
}

.modern-table th {
    background-color: #f8fafc;
    /* slate-50 */
    font-weight: 600;
    color: #475569;
    /* slate-600 */
    text-transform: uppercase;
    font-size: 0.75rem;
    /* 12px */
}

.modern-table td {
    color: #334155;
    /* slate-700 */
}

.modern-table tbody tr:hover {
    background-color: #f8fafc;
    /* slate-50 */
}

.signature-cell {
    word-break: break-all;
    font-family: monospace;
    font-size: 0.8rem;
}

/* --- Responsividad de la Tabla --- */
@media (max-width: 768px) {
    .modern-table thead {
        display: none;
    }

    .modern-table tr {
        display: block;
        border: 1px solid #e2e8f0;
        border-radius: 0.375rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
    }

    .modern-table td {
        display: block;
        text-align: right;
        border-bottom: 1px dotted #cbd5e1;
        padding: 0.75rem 1rem;
    }

    .modern-table td:last-child {
        border-bottom: 0;
    }

    .modern-table td::before {
        content: attr(data-label);
        float: left;
        font-weight: 600;
        color: #475569;
        text-transform: uppercase;
        font-size: 0.75rem;
    }

}

/* --- 7. ESTILOS TARJETA GANADOR (ADMIN) --- */

@keyframes fill-in {
    from {
        width: 0%;
    }

    to {
        width: var(--percentage-width);
    }
}

@keyframes shine-animation {
    0% {
        transform: translateX(-100%) skewX(-30deg);
    }

    100% {
        transform: translateX(200%) skewX(-30deg);
    }
}

.winning-card {
    grid-column: 1 / -1;
    /* Ocupa todo el ancho */
    background: linear-gradient(135deg, #f8fafc 0%, #f0f6ff 100%);
    border: 1px solid #dbeafe;
    box-shadow: 0 10px 20px -5px rgba(22, 96, 222, 0.1);
}

.winning-card h3 {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-size: 1.5rem;
    /* 24px */
    color: #ca8a04;
    /* Color dorado para el trofeo y texto */
    font-weight: 700;
}

.winner-info {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    margin-top: 1rem;
}

.winner-label {
    font-size: 1rem;
    /* 16px */
    font-weight: 500;
    color: #475569;
    margin-bottom: 0.5rem;
}

.winner-name {
    font-size: 2.25rem;
    /* 36px */
    font-weight: 800;
    color: #1e3a8a;
    /* Azul oscuro */
    line-height: 1.1;
    margin-bottom: 0.25rem;
}

.winner-votes {
    font-size: 1.125rem;
    /* 18px */
    font-weight: 600;
    color: #1d4ed8;
    /* Azul */
    margin-bottom: 1.5rem;
}

.winner-percentage-bar {
    width: 100%;
    height: 32px;
    background-color: #e0e7ff;
    border-radius: 16px;
    overflow: hidden;
    position: relative;
    box-shadow: inset 0 2px 4px rgba(0, 0, 0, 0.1);
}

.winner-percentage-fill {
    height: 100%;
    background: linear-gradient(90deg, #4f46e5 0%, #3b82f6 100%);
    /* Gradiente azul/indigo */
    border-radius: 16px 0 0 16px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.875rem;
    /* 14px */
    font-weight: 700;
    color: white;
    overflow: hidden;
    position: relative;
}

.winner-percentage-fill.animated-fill {
    animation: fill-in 1s ease-out forwards;
}

/* Animación de brillo */
.winner-percentage-fill::after {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    width: 50%;
    height: 100%;
    background: linear-gradient(90deg,
            rgba(255, 255, 255, 0) 0%,
            rgba(255, 255, 255, 0.4) 50%,
            rgba(255, 255, 255, 0) 100%);
    animation: shine-animation 3s infinite linear;
}

.runner-up-info {
    margin-top: 1.5rem;
    text-align: center;
}

.runner-up-label {
    font-size: 0.875rem;
    color: #64748b;
    display: block;
}

.runner-up-name {
    font-size: 1.125rem;
    /* 18px */
    font-weight: 600;
    color: #334155;
    margin-right: 0.5rem;
}

.runner-up-votes {
    font-size: 1rem;
    /* 16px */
    color: #64748b;
}

main:has(.auth-form) {
    margin-top: 4rem;
    margin-bottom: 4rem;
}

.auth-form-wrapper {
    display: flex;
    flex-direction: column;
    width: 100%;
    max-width: 560px;
    margin: 0 auto;
}

.auth-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 2rem;
}

.auth-header h2 {
    font-size: 1.5rem;
    /* 24px */
    font-weight: 700;
    color: #1e293b;
    /* slate-900 */
    margin-top: 1rem;
    margin-bottom: 0;
    text-align: center;
}

.auth-form {
    width: 100%;
}

/* Clase de utilidad para botones 100% ancho */
.w-100 {
    width: 100%;
}

.register-link {
    text-align: center;
    margin-top: 1.5rem;
    font-size: 0.875rem;
    /* 14px */
    color: #475569;
    /* slate-600 */
}

.register-link a {
    color: #2563eb;
    /* blue-600 */
    text-decoration: none;
    font-weight: 600;
    transition: all 0.2s ease;
}

.register-link a:hover {
    color: #1d4ed8;
    /* blue-700 */
    text-decoration: underline;
}
```

- Proporcionando una interfaz de usuario limpia y funcional, colorida e intuitiva, mejorando la legibilidad y la usabilidad de la aplicación con los estilos y animaciones simples.

### 6.8. static/js/main.js

Este archivo está actualmente vacío, ya que la lógica JavaScript para el flujo de votación se integró directamente en `user_dashboard.html` para simplificar la gestión de variables y eventos en un proyecto de esta escala. Para proyectos más grandes, se recomendaría externalizar el JavaScript.



---

## 7. Conceptos Criptográficos Clave

La seguridad y la privacidad son pilares de este proyecto, logradas mediante la aplicación de varios conceptos criptográficos.

### 7.1. Hashing de Contraseñas con SHAke128 y Salt

- **SHAke128**: Una función de hash criptográfica de la familia SHA-3 (eXtendable Output Function - XOF). Se utiliza para transformar las contraseñas de los usuarios en una cadena de longitud fija (hash) de manera unidireccional. La elección de SHAke128 cumple con el requisito específico del proyecto.
- **Salt (Sal)**: Una cadena de datos aleatoria y única que se añade a cada contraseña antes de hashearla.
- **Justificación**: Protege contra ataques de tablas arcoíris y hace que los ataques de diccionario y fuerza bruta sean significativamente más costosos, ya que cada contraseña debe ser hasheada con su sal individual.
- **Implementación**: El modelo User genera una sal aleatoria (os.urandom y base64.urlsafe_b64encode) y la almacena junto con el hash de la contraseña generado por hashlib.shake_128.

### 7.2. Criptografía RSA (Clave Pública/Privada)

- **RSA**: Un algoritmo de criptografía asimétrica que utiliza un par de llaves matemáticamente relacionadas:
  - **Clave Privada**: Se mantiene en secreto y se utiliza para crear firmas digitales o desencriptar datos.
  - **Clave Pública**: Se puede compartir libremente y se utiliza para verificar firmas digitales o encriptar datos.
- **Justificación**: Es fundamental para la firma digital de los votos por parte de los usuarios y para el protocolo de firma ciega.
- **Implementación**: La librería cryptography se utiliza para generar pares de llaves RSA de 2048 bits. Las claves públicas se almacenan en la base de datos, mientras que las claves privadas se encriptan con una clave derivada de la contraseña del usuario antes de ser almacenadas, garantizando que solo el usuario con su contraseña pueda acceder a su clave privada.

### 7.3. Firma Digital RSA

- **Proceso**: Un usuario firma un mensaje (su voto) con su clave privada. El resultado es una firma digital. Cualquier persona puede verificar esta firma utilizando la clave pública del usuario.
- **Justificación**: Proporciona autenticidad (confirma que el voto proviene del usuario que dice ser) e integridad (asegura que el voto no ha sido alterado desde que fue firmado).
- **Implementación**: Las funciones sign_message() y verify_signature() en crypto_utils.py implementan este proceso utilizando el esquema PSS (Probabilistic Signature Scheme) con SHA256, un estándar seguro para firmas RSA.

### 7.4. Firma Ciega RSA

- **Proceso**: Permite a una autoridad (en este caso, el sistema de votación) firmar un mensaje (el voto) sin conocer su contenido. El votante "ciega" su voto, la autoridad lo firma, y luego el votante "descega" la firma para obtener una firma válida sobre su voto original.
- **Justificación**: Es crucial para la privacidad en sistemas de votación. Garantiza que la autoridad que emite la firma (que valida el voto) no pueda vincular la identidad del votante con el contenido de su voto final.
- **Implementación**:
  - Se utiliza un par de llaves RSA específico para la "Autoridad de Votación".
  - Las funciones blind_message(), sign_blinded_message(), unblind_signature() y verify_blind_signature() en crypto_utils.py implementan los pasos matemáticos del protocolo de firma ciega RSA.
  - Para simplificar el proyecto de licenciatura, el proceso de cegado/descegado se realiza en el servidor, lo que significa que el servidor conoce el voto inicial antes de cegarlo. Sin embargo, el token de firma ciega descegado garantiza que la autoridad no pueda vincular la solicitud inicial con el voto final que el usuario envía, manteniendo el principio de privacidad del voto.


---

## 8. Pruebas y Verificación

El desarrollo se realizó de forma iterativa, con pruebas en cada etapa para asegurar la funcionalidad y la correcta aplicación de los conceptos criptográficos.

### 8.1. Proceso de Pruebas

- **Configuración del Entorno**: Verificación de la instalación de Homebrew y tools de c++ en Windows, Python y las librerías.
- **Arranque de Flask**: Confirmación de que la aplicación Flask se inicia correctamente y sirve la página de inicio.
- **Autenticación**:
  - Registro de usuarios (convencionales y administradores) con diferentes credenciales.
  - Pruebas de validación de formularios (campos vacíos, contraseñas no coincidentes, nombres de usuario duplicados).
  - Verificación de inicio y cierre de sesión.
  - Confirmación de que current_user.is_authenticated y current_user.user_type funcionan correctamente para controlar el acceso.
- **Generación de Llaves RSA**:
  - Registro de usuarios convencionales y verificación de la descarga de public.pem.
  - Inspección de la base de datos para confirmar que public_key y private_key_encrypted se almacenan.
- **Firma Ciega y Votación**:
  - Solicitud de tokens de firma ciega para diferentes opciones de voto.
  - Verificación de que el botón "Enviar Voto Final" se habilita correctamente.
  - Envío de votos con la contraseña de la clave privada.
  - Pruebas de doble voto para la misma opción, verificando que el sistema lo previene.
  - Verificación de la base de datos para confirmar que los BlindSignatureToken se marcan como is_used y que los Vote se registran con sus firmas.
- **Dashboards**:
  - Acceso al panel de usuario para ver votos y tokens pendientes.
  - Acceso al panel de administrador para ver las estadísticas de votación.
- **Actualización de Base de Datos**: Para cada cambio en el esquema de la base de datos (modelos), se eliminó el archivo site.db y se permitió que db.create_all() lo recreara, lo cual es una práctica estándar en desarrollo local para proyectos pequeños.

### 8.2. Uso de la Clave Pública para Auditoría Externa

Aunque el flujo de votación requiere que el usuario ingrese su clave pública en cada paso (el servidor la puede almacenar y usar internamente para verificar la firma del usuario), la descarga de la clave pública es fundamental para la auditoría externa y para el funcionamiento del voto (este ultimo para realizar la accion de envio con fines practicos).

Se planteó la posibilidad de una herramienta externa (un script Python, por ejemplo) que, dada la opción de voto, el token de firma ciega, la firma final del usuario, la clave pública del usuario y la clave pública de la autoridad, pueda verificar de forma independiente:

- Que el token de firma ciega es una firma válida de la Autoridad sobre el hash del voto.
- Que la firma final del usuario es válida para el voto y el token, utilizando la clave pública del usuario.

Esta capacidad de verificación externa es un pilar de la transparencia y la confianza en sistemas de votación criptográficos.



---

## 9. Consideraciones y Mejoras Futuras

Aunque el proyecto cumple con los requisitos para un nivel de licenciatura, existen varias áreas para futuras mejoras y consideraciones para un sistema de producción:

- **Criptografía en el Cliente (Frontend)**: Para una privacidad de voto aún mayor, el proceso de cegado/descegado y la firma con la clave privada del usuario deberían realizarse completamente en el navegador del cliente (JavaScript), sin enviar la contraseña de la clave privada al servidor. Esto requiere librerías criptográficas JavaScript y un diseño más complejo del frontend.
- **Gestión de Opciones de Voto**: Implementar un sistema de gestión de opciones de voto dinámico a través de una interfaz de administrador, en lugar de hardcodearlas en el código.
- **Interfaz de Usuario (UI/UX)**: Mejorar el diseño visual y la experiencia de usuario utilizando frameworks CSS/JS como Bootstrap o React/Vue.js.
- **Persistencia de Sesiones**: Mejorar la gestión de sesiones para usuarios que cierran el navegador o se desconectan.
- **Escalabilidad**: Para un sistema con muchos usuarios, se necesitaría una base de datos más robusta (PostgreSQL, MySQL) y un servidor de aplicaciones más escalable.
- **Seguridad Adicional**:
  - Implementar autenticación de dos factores (2FA).
  - Mejorar la derivación de clave para Fernet utilizando PBKDF2HMAC con sal para la encriptación de la clave privada.
  - Auditoría de seguridad y pruebas de penetración.
- **Despliegue en Producción**: Configurar la aplicación para un despliegue en un servidor de producción (por ejemplo, con Gunicorn/Nginx o Docker).


---

## 10. Conclusión

Este proyecto ha demostrado exitosamente la implementación de un sistema de votación digital que incorpora principios criptográficos avanzados para garantizar la autenticidad, integridad y privacidad del voto. Se ha logrado un portal de autenticación seguro con hashing de contraseñas (SHAke128 con sal), gestión de llaves RSA para usuarios, y un flujo de votación que utiliza la firma ciega RSA. La arquitectura basada en Flask y SQLite ha permitido un desarrollo ágil y una comprensión clara de cada componente, cumpliendo con los objetivos de un proyecto a nivel de licenciatura. La capacidad de verificar los votos de forma independiente mediante las claves públicas subraya la transparencia inherente a este tipo de sistemas.

El trabajo realizado sienta una base sólida para futuras exploraciones en la criptografía aplicada y el desarrollo de sistemas seguros.
