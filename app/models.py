from app import db, login_manager
from flask_login import UserMixin
from cryptography.fernet import Fernet
import os

# Define the key file path
KEY_FILE_PATH = "app/static/key/secure_key.txt"

def load_secret_key():
    """Load the encryption key from the file."""
    if not os.path.exists(KEY_FILE_PATH):
        raise FileNotFoundError(f"Encryption key file not found at {KEY_FILE_PATH}")

    with open(KEY_FILE_PATH, "rb") as key_file:
        return key_file.read().strip()  # Read and strip any extra spaces/newlines

# Load the key at runtime
SECRET_KEY = load_secret_key()

def encrypt_password(plain_text):
    cipher = Fernet(SECRET_KEY)
    return cipher.encrypt(plain_text.encode()).decode()

def decrypt_password(encrypted_text):
    cipher = Fernet(SECRET_KEY)
    return cipher.decrypt(encrypted_text.encode()).decode()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)  # Added name field
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    profile_picture = db.Column(db.LargeBinary, nullable=True)  # Changed profile picture to binary

    def __repr__(self):
        return f"User('{self.username}', '{self.name}', '{self.email}')"


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    url = db.Column(db.String(255), nullable=False)
    password_encrypted = db.Column(db.String(256), nullable=False)  # Encrypted password storage
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

    def __repr__(self):
        return f"Password('{self.name}', '{self.url}', '****')"

    def set_password(self, plain_password):
        """Encrypt and store the password"""
        self.password_encrypted = encrypt_password(plain_password)

    def get_password(self):
        """Decrypt and return the password"""
        return decrypt_password(self.password_encrypted)