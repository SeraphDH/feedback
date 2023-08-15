from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Create the SQLAlchemy database object
db = SQLAlchemy()



class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)
    first_name = db.Column(db.String(30), nullable=False)
    last_name = db.Column(db.String(30), nullable=False)
    
    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, bcrypt, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User(username='{self.username}', email='{self.email}', first_name='{self.first_name}', last_name='{self.last_name}')>"

class Feedback(db.Model):
    __tablename__ = 'feedback'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship('User', backref='feedbacks')
    
    def __repr__(self):
        return f"<Feedback(title='{self.title}', user='{self.user.username}')>"
    
    @classmethod
    def get_feedback_by_user(cls, user_id):
        return cls.query.filter_by(user_id=user_id).all()