<h1 align="center">UNIVERSIDAD NACIONAL AUTÓNOMA DE MÉXICO</h1>
<h2 align="center">FACULTAD DE INGENIERÍA</h2>
<h3 align="center">INGENIERÍA EN COMPUTACIÓN</h3>
<h3 align="center"> 📌 Criptografía 📌 </h3>

<h2 align="center">Proyecto Final: Sistema de votación digital con firma ciega</h2>

&nbsp;
&nbsp;

### **NOMBRE COMPLETO:**  
**Carandia Lorenzo Brenda Fernanda**  <br>
**Cuadriello Valdés Cynthia Citlalli**<br>
**Cuadriello Valdés Diana Sinsuni**<br>
**Jose Laguna Daniel** <br>
**López Sugahara Ernesto Danjiro**<br>
**Rodriguez Kobeh Santiago**
 

### **GRUPO:**  
**02**  

### **Semestre:**  
**2026-1**  

&nbsp;
&nbsp;

# Instrucciones

---

## Preparación del Entorno de Desarrollo

### 1. MacOS

Para configurar el entorno en una MacBook, se siguieron los siguientes pasos:

&nbsp;

#### 1.1. Xcode Command Line Tools 

**Propósito:** Proporciona compiladores y herramientas esenciales (como gcc) que muchas librerías de Python, especialmente las criptográficas, requieren para compilar componentes nativos durante la instalación.

**Instalación:**

```bash
xcode-select --install
```

&nbsp;

#### 1.2. Homebrew 

**Propósito:** Gestor de paquetes para macOS que simplifica la instalación y gestión de software de desarrollo que no viene preinstalado con el sistema operativo.

**Instalación:** 

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Verificación:** 

```bash
brew --version
```

&nbsp;

#### 1.3. Python 3 

**Propósito:** Instalar una versión moderna de Python 3, separada de la versión preinstalada de macOS.

**Instalación:** 

```bash
brew install python
```

**Verificación:** 

```bash
python3 --version
```

&nbsp;

#### 1.4. Entorno Virtual (venv) 

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

&nbsp;

#### 1.5. Instalación de Librerías Python 

**Propósito:** Instalar todas las dependencias del proyecto dentro del entorno virtual activo.

**Instalación:**

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF cryptography
```
**Segunda opción:** Puedes utilizar también esta opción para instalar las librerías

```bash
pip install -r requirements.txt
```

**Verificación:** 

```bash
pip list
```

&nbsp;

### 2. Windows 

Para configurar el entorno en una máquina con Windows 10/11, se siguieron los siguientes pasos:

&nbsp;

#### 2.1. Microsoft C++ Build Tools 

**Propósito:** Proporciona compiladores y herramientas esenciales de ejecucion que utilizan librerias de Python como cryptography, para compilar componentes nativos durante su instalacion.

**Instalación:** 

Acceder a la pagina oficial de descargas de Visual Studio: *https://visualstudio.microsoft.com/es/downloads/*

Descargar "Build Tools para Visual Studio" 

Se ejecuta el programa y se selecciona la opcion de "Desarrollo para el escritorio con C++"

&nbsp;

#### 2.2. Python 

**Propósito:** Instalar una version actual de Python 3

**Instalación:** 

Acceder a la pagina oficial de descargas de Python, para descargar la version mas reciente del instalador: 

Al ejecutarlo se selecciona la casilla "Add Python X.X to PATH" y se instala.

**Verificación:** 

```bash
python --version
```

&nbsp;

#### 2.3. Entorno Virtual (venv) 

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

&nbsp;

#### 2.4. Instalación de Librerías Python 

**Propósito:** Instalar todas las dependencias del proyecto dentro del entorno virtual activo.

**Instalación:**

```bash
pip install Flask Flask-SQLAlchemy Flask-Login Flask-WTF cryptography
```
**Segunda opción:** Puedes utilizar también esta opción para instalar las librerías

```bash
pip install -r requirements.txt
```

**Verificación:** 

```bash
pip list
```

&nbsp;

## Ejecución

### 1. MacOS
Para ejecutar el programa en una MacBook, se siguieron los siguientes pasos:

```bash
cd ~/Documents/
cd votacion_digital
source venv/bin/activate
python3 app.py
```

&nbsp;

### 2. Windows 
Para ejecutar el programa en una máquina con Windows 10/11, se siguieron los siguientes pasos:

```bash
cd ~/Documents/
cd votacion_digital
venv\Scripts\activate.bat
python app.py
```


&nbsp;

## Acceso al sistema
Una vez que el servidor esté ejecutándose, abre tu navegador web  e ingresa a la siguiente dirección, o simplemente da clic en ella desde la terminal:

```bash
http://127.0.0.1:5000
```

Esto abrirá la página principal de la plataforma de votación.
Desde allí, podrás acceder con tu cuenta existente o registrarte como un nuevo usuario, seleccionando el rol correspondiente ("convencional" o "administrador").

#### Nota: El sistema se encarga de gestionar la base de datos automáticamente; cualquier registro o voto realizado se guardará de forma segura e inmediata.

&nbsp;
&nbsp;

---
## Versiones de paquetes
Al momento de ejecutar el programa se cuentan con las siguiente versiones

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


&nbsp;
&nbsp;

---

# GitHub

**Enlace:** https://github.com/BrendaCarandia/Practicas-de-Criptograf-a.git

