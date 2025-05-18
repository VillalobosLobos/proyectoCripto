from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Ruta de almacenamiento de claves
PRIVATE_KEY_FILE = "ecc_private_key.pem"
PUBLIC_KEY_FILE = "ecc_public_key.pem"

# Función para generar y guardar las claves ECC
def generate_and_save_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Guardar clave privada
    with open(PRIVATE_KEY_FILE, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Guardar clave pública
    with open(PUBLIC_KEY_FILE, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("Claves generadas y guardadas.")

# Función para cargar claves ECC desde archivos
def load_keys():
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    with open(PUBLIC_KEY_FILE, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())

    return private_key, public_key

# Derivar una clave de sesión AES
def derive_session_key(private_key, public_key):
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session-key'
    ).derive(shared_secret)

# Cifrar una nota
def encrypt_note(plain_text, session_key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_note = encryptor.update(plain_text.encode('utf-8')) + encryptor.finalize()
    return iv + encrypted_note

# Descifrar una nota
def decrypt_note(encrypted_data, session_key):
    iv = encrypted_data[:16]
    encrypted_note = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(session_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_note) + decryptor.finalize()).decode('utf-8')

# Programa principal
if __name__ == "__main__":
    # Si no existen las claves, generarlas
    if not os.path.exists(PRIVATE_KEY_FILE) or not os.path.exists(PUBLIC_KEY_FILE):
        generate_and_save_keys()

    # Cargar las claves
    private_key, public_key = load_keys()

    # Derivar la clave de sesión
    session_key = derive_session_key(private_key, public_key)

    # Ingreso de nota
    note = input("Ingresa nota: ")
    print(f"Nota original: {note}")

    # Cifrar
    encrypted_note = encrypt_note(note, session_key)
    print(f"Nota cifrada (bytes): {encrypted_note}")

    # Descifrar
    decrypted_note = decrypt_note(encrypted_note, session_key)
    print(f"Nota descifrada: {decrypted_note}")

