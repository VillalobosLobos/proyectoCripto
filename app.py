from flask import Flask, render_template, request, redirect, session, url_for
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from werkzeug.security import generate_password_hash
from werkzeug.security import check_password_hash
from db.models import db, Psychologist, Note, Access
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # para manejar sesiones

# Configuración base de datos SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.abspath('db/data.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

# Crear tablas si no existen
with app.app_context():
    db.create_all()

#Para cargar la clave privada de un psicologo
def load_key_private(email):
    PRIVATE_KEY_FILE = f'private_keys/{email}_ecc_private_key.pem'
    with open(PRIVATE_KEY_FILE, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    return private_key

# Derivar una clave de sesión AES
def derive_session_key(private_key, public_key):
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session-key'
    ).derive(shared_secret)

# Cifrar la nota
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

def encrypt_session_key_for_receiver(private_key_sender, public_key_receiver, session_key):
    # ✅ CORRECTO: especifica ec.ECDH()
    shared_key = private_key_sender.exchange(ec.ECDH(), public_key_receiver)

    # Derivar clave simétrica con HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session key encryption',
        backend=default_backend()
    ).derive(shared_key)

    # Cifrar la clave de sesión AES con AES-CFB
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_session_key = encryptor.update(session_key) + encryptor.finalize()

    return iv + encrypted_session_key

@app.route('/')
def index():
    return 'Bienvenido al sistema de notas psicológicas seguras'

#Para cerrar sesión
@app.route('/logout')
def logout():
    return redirect(url_for('login'))

#Para iniciar sesión tu
@app.route('/login',methods=['GET','POST'])
def login():
    #Si vamos a iniciar sesión en fa
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']

        valid_user=Psychologist.query.filter_by(email=email).first()

        #Para ver si es válido o nelson un psicologo
        if valid_user and check_password_hash(valid_user.password_hash,password):
            session['user_id'] = valid_user.id  # <- Aquí se guarda el ID del psicologo
            return redirect(url_for('main_panel'))
        else:
            print('Correo o contraseña no válidos')

    return render_template('login.html')

#Para regstrar un nuevo psicologo
@app.route('/register',methods=['POST','GET'])
def register():
    if request.method=='POST':
        email=request.form['email']
        password=request.form['password']

        passwordHash=generate_password_hash(password)

        # Generar clave ECC con curva NIST P-256
        private_key = ec.generate_private_key(ec.SECP256R1())  # NIST P-256
        public_key = private_key.public_key()

        # Serializar clave pública (para guardar en DB)
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        #Crear una instancia para agregar un psicologo
        new_user=Psychologist(
            email=email,
            password_hash=passwordHash,
            ecc_public_key=public_pem
        )

        #Guardarlo en la base de datos
        existing = Psychologist.query.filter_by(email=email).first()
        if existing:
            print('Ya existe esa cuenta')
            return redirect(url_for('register'))
        else:
            db.session.add(new_user)
            db.session.commit()

            #Guardamos la clave privada en el servidor
            with open(f'private_keys/{email}_ecc_private_key.pem', 'wb') as f:
                f.write(
                    private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                    )
                )
            print(f'Usuario {email} creado correctamente')
            return redirect(url_for('login'))

    return render_template('register.html')

#Está ruta será el panel o página principal de un psicologo
@app.route('/main_panel')
def main_panel():
    return render_template('main_panel.html')

#Para crear una nota
@app.route('/create_note', methods=['GET', 'POST'])
def create_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        note_text = request.form['note']
        title = request.form.get('title', 'Sin título')
        correos = request.form.get('correos_autorizados', '').split(',')

        # Psicólogo autor
        user = db.session.get(Psychologist, session['user_id'])
        email_autor = user.email
        private_key_autor = load_key_private(email_autor)

        # Clave de sesión (AES) aleatoria
        session_key = os.urandom(32)  # AES-256

        # Cifrar la nota
        encrypted_note = encrypt_note(note_text, session_key)

        # Guardar la nota
        nueva_nota = Note(
            psychologist_id=user.id,
            title=title,
            encrypted_note=encrypted_note
        )
        db.session.add(nueva_nota)
        db.session.commit()

        # Compartir clave con cada psicólogo autorizado
        for correo in correos:
            correo = correo.strip()
            if not correo:
                continue

            psicologo = Psychologist.query.filter_by(email=correo).first()
            if psicologo:
                try:
                    public_key_receiver = serialization.load_pem_public_key(
                        psicologo.ecc_public_key.encode('utf-8')
                    )
                    encrypted_session_key = encrypt_session_key_for_receiver(
                        private_key_autor,
                        public_key_receiver,
                        session_key
                    )
                    acceso = Access(
                        note_id=nueva_nota.id,
                        psychologist_id=psicologo.id,
                        encrypted_session_key=encrypted_session_key
                    )
                    db.session.add(acceso)
                except Exception as e:
                    print(f"Error compartiendo con {correo}: {e}")
            else:
                print(f"Psicólogo con correo {correo} no encontrado.")

        db.session.commit()
        return redirect(url_for('main_panel'))

    return render_template('create_note.html')

#Para ver las notas
@app.route('/view_notes')
def view_notes():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(Psychologist, session['user_id'])
    email = user.email
    private_key = load_key_private(email)
    public_key = user.ecc_public_key
    public_key_obj = serialization.load_pem_public_key(public_key.encode('utf-8'))
    session_key = derive_session_key(private_key, public_key_obj)

    notes_query = Note.query.filter_by(psychologist_id=user.id).all()
    
    notes = []
    for note in notes_query:
        try:
            decrypted = decrypt_note(note.encrypted_note, session_key)
            notes.append({
                'id': note.id,
                'title': note.title,
                'note_content': decrypted
                })

        except Exception as e:
            print(f"Error al descifrar nota {note.id}: {e}")

    return render_template('view_notes.html', notes=notes)

#Para ver una nora
@app.route('/view_note/<int:note_id>')
def view_note(note_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    # Obtener usuario
    user = db.session.get(Psychologist, session['user_id'])
    email = user.email
    private_key = load_key_private(email)
    public_key_obj = serialization.load_pem_public_key(user.ecc_public_key.encode('utf-8'))
    session_key = derive_session_key(private_key, public_key_obj)

    # Obtener nota
    note = Note.query.filter_by(id=note_id, psychologist_id=user.id).first()
    if not note:
        return "Nota no encontrada o no tienes permiso", 404

    # Descifrar
    try:
        decrypted = decrypt_note(note.encrypted_note, session_key)
    except Exception as e:
        print(f"Error al descifrar la nota: {e}")
        decrypted = "[Error al descifrar nota]"

    return render_template('show_note.html', content=decrypted, title=note.title)

#Para eliminar una nota
@app.route('/delete_note', methods=['GET', 'POST'])
def delete_note():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = db.session.get(Psychologist, session['user_id'])

    if request.method == 'POST':
        note_id = request.form['note_id']
        note = Note.query.filter_by(id=note_id, psychologist_id=user.id).first()
        
        if note:
            db.session.delete(note)
            db.session.commit()
            return redirect(url_for('view_notes'))
        else:
            return "Nota no encontrada o no tienes permiso para eliminarla", 404

    notes = Note.query.filter_by(psychologist_id=user.id).all()
    return render_template('delete_note.html', notes=notes)

if __name__ == '__main__':
    app.run(debug=True)
