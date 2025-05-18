from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Psychologist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    ecc_public_key = db.Column(db.Text, nullable=False)

    # Relaciones
    notes = db.relationship('Note', backref='author', lazy=True)
    shared_notes = db.relationship('Access', backref='psychologist', lazy=True)

class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('psychologist.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    encrypted_note = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Agrega cascade para que Access se borre automáticamente con la nota
    access_list = db.relationship('Access', backref='note', cascade="all, delete-orphan", lazy=True)

class Access(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False)
    psychologist_id = db.Column(db.Integer, db.ForeignKey('psychologist.id'), nullable=False)
    encrypted_session_key = db.Column(db.LargeBinary, nullable=False)
