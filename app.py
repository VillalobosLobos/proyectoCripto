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
        title = request.form['title']
        content = request.form['content']
        emails = request.form.getlist('emails[]')  # Correos adicionales

        # Obtener el psicólogo actual
        author = db.session.get(Psychologist, session['user_id'])
        if not author:
            return "Usuario no encontrado", 404

        author_email = author.email
        author_private_key = load_key_private(author_email)

        # Generar clave AES de sesión para cifrar la nota
        session_key = os.urandom(32)

        # Cifrar la nota con la clave AES
        encrypted_note = encrypt_note(content, session_key)

        # Crear y guardar la nota
        note = Note(
            title=title,
            encrypted_note=encrypted_note,
            psychologist_id=author.id
        )
        db.session.add(note)
        db.session.commit()  # IMPORTANTE para que note.id se asigne

        print(f"Nota creada con ID: {note.id}")

        # Asegurar que el autor esté en la lista de correos para compartir
        all_emails = set(emails)
        all_emails.add(author_email)

        for email in all_emails:
            user = Psychologist.query.filter_by(email=email).first()
            if not user:
                print(f"Usuario no encontrado para email: {email}, se omite")
                continue

            # Cargar clave pública del receptor
            public_key_user = serialization.load_pem_public_key(user.ecc_public_key.encode('utf-8'))

            # Derivar clave compartida para cifrar la clave AES
            shared_key = author_private_key.exchange(ec.ECDH(), public_key_user)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'session key encryption',
                backend=default_backend()
            ).derive(shared_key)

            # Cifrar la clave AES (session_key) para cada receptor
            iv = os.urandom(16)
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_session_key = iv + encryptor.update(session_key) + encryptor.finalize()

            access = Access(
                note_id=note.id,
                psychologist_id=user.id,
                encrypted_session_key=encrypted_session_key
            )
            db.session.add(access)

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

    notes = []

    accesses = Access.query.filter_by(psychologist_id=user.id).all()

    for access in accesses:
        note = access.note
        author = Psychologist.query.get(note.psychologist_id)

        try:
            # Derivar clave con ECDH entre clave privada del usuario y clave pública del autor
            author_public_key = serialization.load_pem_public_key(author.ecc_public_key.encode('utf-8'))
            shared_key = private_key.exchange(ec.ECDH(), author_public_key)
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'session key encryption',
                backend=default_backend()
            ).derive(shared_key)

            # Descifrar clave de sesión
            iv = access.encrypted_session_key[:16]
            encrypted_key = access.encrypted_session_key[16:]
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            session_key = decryptor.update(encrypted_key) + decryptor.finalize()

            # Descifrar nota
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

    # Obtener usuario actual
    user = db.session.get(Psychologist, session['user_id'])
    email = user.email
    private_key = load_key_private(email)

    # Buscar nota y verificar acceso
    access = Access.query.filter_by(note_id=note_id, psychologist_id=user.id).first()
    if not access:
        return "No tienes acceso a esta nota", 403

    # Obtener la nota
    note = Note.query.get(note_id)
    if not note:
        return "Nota no encontrada", 404

    # Obtener clave pública del autor
    author = Psychologist.query.get(note.psychologist_id)
    public_key_author = serialization.load_pem_public_key(author.ecc_public_key.encode('utf-8'))

    # Derivar clave simétrica a partir de ECDH
    shared_key = private_key.exchange(ec.ECDH(), public_key_author)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'session key encryption',
        backend=default_backend()
    ).derive(shared_key)

    # Descifrar la clave de sesión AES
    encrypted_session_key = access.encrypted_session_key
    iv = encrypted_session_key[:16]
    encrypted_key = encrypted_session_key[16:]

    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    session_key = decryptor.update(encrypted_key) + decryptor.finalize()

    # Usar esa clave para descifrar la nota
    try:
        decrypted_note = decrypt_note(note.encrypted_note, session_key)
    except Exception as e:
        print(f"Error al descifrar la nota: {e}")
        decrypted_note = "[Error al descifrar nota]"

    return render_template('show_note.html', title=note.title, content=decrypted_note)

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
            return redirect(url_for('main_panel'))
        else:
            return "Nota no encontrada o no tienes permiso para eliminarla", 404

    notes = Note.query.filter_by(psychologist_id=user.id).all()
    return render_template('delete_note.html', notes=notes)

if __name__ == '__main__':
    app.run(debug=True)
