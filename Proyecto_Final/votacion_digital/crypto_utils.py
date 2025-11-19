from cryptography.hazmat.primitives.asymmetric import rsa, padding
# from cryptography.hazmat.primitives.asymmetric.utils import encode_parameters_for_rfc6979 # Para el hash del mensaje
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet # Para encriptar la clave privada de forma simétrica
import base64
import hashlib
import os
import random
import math

# --- Funciones para RSA ---

def generate_rsa_key_pair():
    """
    Genera un par de llaves RSA (privada y pública).
    Retorna la clave privada y pública en formato PEM.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048, # Un tamaño de clave de 2048 bits es un buen estándar
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serializar la clave privada a formato PEM sin encriptar (para luego encriptarla nosotros)
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption() # No la encriptamos aquí
    )

    # Serializar la clave pública a formato PEM
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_private_key.decode('utf-8'), pem_public_key.decode('utf-8')

def encrypt_private_key(private_key_pem, passphrase):
    """
    Encripta una clave privada RSA PEM usando una passphrase derivada
    y Fernet (cifrado simétrico).
    """
    # Derivar una clave simétrica de la passphrase para Fernet
    # Usaremos PBKDF2HMAC para derivar una clave segura
    kdf = Fernet.generate_key() # Generamos una clave Fernet para el ejemplo,
                                # pero en un escenario real, la clave Fernet
                                # debería derivarse de la passphrase del usuario
                                # de forma determinística y segura.
                                # Para simplificar el proyecto de licenciatura,
                                # usaremos la passphrase directamente como clave Fernet
                                # (aunque no es la práctica más segura, es didáctica).

    # NOTA: Para un uso real, se usaría un KDF (Key Derivation Function) como PBKDF2HMAC
    # para derivar una clave Fernet de la passphrase.
    # Por ejemplo:
    # from cryptography.hazmat.primitives import hashes
    # from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    # from cryptography.hazmat.backends import default_backend
    # salt_kdf = os.urandom(16) # Una sal para el KDF
    # kdf = PBKDF2HMAC(
    #     algorithm=hashes.SHA256(),
    #     length=32,
    #     salt=salt_kdf,
    #     iterations=100000,
    #     backend=default_backend()
    # )
    # fernet_key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
    # fernet = Fernet(fernet_key)
    #
    # Para este proyecto, simplificaremos y usaremos una clave Fernet generada
    # que se pasará en el momento de la encriptación/desencriptación.
    # Esto significa que la "passphrase" que se usa para encriptar/desencriptar
    # es en realidad la clave Fernet misma, o se deriva de ella.
    # Para que sea más didáctico con la passphrase del usuario:
    # Vamos a usar la contraseña del usuario directamente como clave para Fernet
    # después de un simple hashing para asegurar la longitud correcta.
    # Esto NO ES SEGURO para producción, pero ilustra el concepto para licenciatura.

    # Derivar una clave Fernet a partir de la contraseña del usuario (passphrase)
    # Esto es una simplificación para el proyecto de licenciatura.
    # En producción, usarías un KDF como PBKDF2HMAC con una sal para derivar la clave.
    key_material = hashlib.sha256(passphrase.encode('utf-8')).digest()
    fernet_key = base64.urlsafe_b64encode(key_material)
    fernet = Fernet(fernet_key)

    encrypted_private_key = fernet.encrypt(private_key_pem.encode('utf-8'))
    return encrypted_private_key.decode('utf-8') # Almacenar como string

def decrypt_private_key(encrypted_private_key_str, passphrase):
    """
    Desencripta una clave privada RSA PEM encriptada usando una passphrase.
    """
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
    """Carga una clave privada RSA desde su formato PEM."""
    return serialization.load_pem_private_key(
        pem_data.encode('utf-8'),
        password=password.encode('utf-8') if password else None,
        backend=default_backend()
    )

def load_public_key_from_pem(pem_data):
    """Carga una clave pública RSA desde su formato PEM."""
    return serialization.load_pem_public_key(
        pem_data.encode('utf-8'),
        backend=default_backend()
    )

def sign_message(private_key_pem, message, passphrase=None):
    """
    Firma un mensaje usando la clave privada.
    """
    # Nota: `private_key_pem` aquí debe ser el PEM de la clave privada en texto plano
    # (por ejemplo, obtenido tras desencriptar con Fernet). No debemos pasar la
    # passphrase a `load_pem_private_key` a menos que el PEM esté protegido con
    # una contraseña en formato PEM. En este proyecto la encriptación se hace
    # externamente con Fernet, por eso no esperamos una contraseña PEM aquí.
    private_key = load_private_key_from_pem(private_key_pem, password=None)

    # Usar la API moderna: private_key.sign(...)
    signature = private_key.sign(
        message.encode('utf-8'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem, message, signature_b64):
    """
    Verifica una firma usando la clave pública.
    """
    public_key = load_public_key_from_pem(public_key_pem)
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
    
# --- Funciones para Firma Ciega RSA ---

def generate_and_save_authority_keys(private_path="authority_private_key.pem", public_path="authority_public_key.pem"):
    """
    Genera un par de llaves RSA para la autoridad de firma y las guarda en archivos PEM.
    Solo debe ejecutarse una vez.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Guardar clave privada
    with open(private_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption() # Sin encriptar para simplificar el acceso en el servidor
        ))

    # Guardar clave pública
    with open(public_path, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Llaves de autoridad generadas y guardadas en {private_path} y {public_path}")

def load_authority_private_key(path="authority_private_key.pem"):
    """Carga la clave privada de la autoridad desde un archivo PEM."""
    with open(path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None, # No hay contraseña ya que la guardamos sin encriptar
            backend=default_backend()
        )
    return private_key

def load_authority_public_key(path="authority_public_key.pem"):
    """Carga la clave pública de la autoridad desde un archivo PEM."""
    with open(path, "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    return public_key

# Funciones para la firma ciega
# Función para calcular el máximo común divisor (GCD)
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

# Función para calcular el inverso modular (a^-1 mod m)
def modinv(a, m):
    # Algoritmo extendido de Euclides
    m0 = m
    x0 = 0
    x1 = 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 = x1 + m0
    return x1

def blind_message(message_hash_int, public_key_authority):
    """
    Ciega un hash de mensaje entero usando la clave pública de la autoridad.
    Retorna el mensaje cegado (entero) y el factor de cegado (entero).
    """
    # Obtenemos los componentes numéricos de la clave pública de la autoridad
    # n = modulo, e = exponente público
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    # Generar un factor de cegado 'r' aleatorio
    # r debe ser 1 < r < n y gcd(r, n) = 1
    while True:
        r = random.randrange(2, n - 1)
        if gcd(r, n) == 1:
            break

    # Calcular el mensaje cegado: m_cegado = (message_hash_int * r^e) mod n
    # pow(base, exp, mod) es eficiente para esto
    blinded_message_int = (message_hash_int * pow(r, e, n)) % n
    return blinded_message_int, r

def sign_blinded_message(blinded_message_int, private_key_authority):
    """
    Firma un mensaje cegado (entero) usando la clave privada de la autoridad.
    Retorna la firma cegada (entero).
    """
    # Obtenemos los componentes numéricos de la clave privada de la autoridad
    # n = modulo, d = exponente privado
    private_numbers = private_key_authority.private_numbers()
    n = private_numbers.public_numbers.n

    d = private_numbers.d

    # Calcular la firma cegada: s_cegado = (blinded_message_int^d) mod n
    signed_blinded_message_int = pow(blinded_message_int, d, n)
    return signed_blinded_message_int

def unblind_signature(signed_blinded_message_int, r, public_key_authority):
    """
    Desciega la firma cegada para obtener la firma real del mensaje original.
    Retorna la firma real (entero).
    """
    # Obtenemos los componentes numéricos de la clave pública de la autoridad
    # n = modulo
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n

    # Calcular el inverso modular de r: r_inv = r^(-1) mod n
    r_inv = modinv(r, n)

    # Descegar la firma: s = (signed_blinded_message_int * r_inv) mod n
    unblinded_signature_int = (signed_blinded_message_int * r_inv) % n
    return unblinded_signature_int

def verify_blind_signature(message_hash_int, unblinded_signature_int, public_key_authority):
    """
    Verifica una firma ciega descegada usando la clave pública de la autoridad.
    Retorna True si la firma es válida, False en caso contrario.
    """
    public_numbers = public_key_authority.public_numbers()
    n = public_numbers.n
    e = public_numbers.e

    # Verificar si (firma^e) mod n == mensaje_hash_int
    return message_hash_int == pow(unblinded_signature_int, e, n)

# --- Funciones para convertir hashes a enteros para operaciones RSA ---
def hash_message_to_int(message):
    """
    Hashea un mensaje con SHA256 y lo convierte a un entero.
    """
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(message.encode('utf-8'))
    message_hash_bytes = digest.finalize()
    # Convertir bytes a entero
    return int.from_bytes(message_hash_bytes, 'big')