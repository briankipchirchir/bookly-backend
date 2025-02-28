from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime

db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow) 

    # One-to-Many: A user can have multiple favorites
    favorites = db.relationship('Favorite', back_populates='user', cascade="all, delete-orphan")

    # One-to-Many: A user can have multiple reading history entries
    reading_history = db.relationship('ReadingHistory', back_populates='user', cascade="all, delete-orphan")

    def set_password(self, password):
        """Hash password before storing"""
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        """Verify hashed password"""
        return bcrypt.check_password_hash(self.password_hash, password)

class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Gutenberg Book ID
    title = db.Column(db.String(255), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    image_url = db.Column(db.String(255), nullable=True)
    description = db.Column(db.Text, nullable=True)

    # One-to-Many: A book can be in multiple user's favorites
    favorites = db.relationship('Favorite', back_populates='book', cascade="all, delete-orphan")

    # One-to-Many: A book can be in multiple users' reading history
    reading_history_entries = db.relationship('ReadingHistory', back_populates='book', cascade="all, delete-orphan")

class Favorite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "book_id": self.book_id
        }

    # Relationships
    user = db.relationship('User', back_populates='favorites')
    book = db.relationship('Book', back_populates='favorites')

class ReadingHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    book_id = db.Column(db.Integer, db.ForeignKey('book.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    # Relationships
    user = db.relationship('User', back_populates='reading_history')
    book = db.relationship('Book', back_populates='reading_history_entries')
