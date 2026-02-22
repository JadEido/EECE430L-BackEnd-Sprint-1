#import from here to avoid circular import issues
from extensions import db, bcrypt, ma
from datetime import datetime

class User(db.Model):
    def __init__(self, user_name, password, role='user', email=None):
        self.user_name = user_name
        self.hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        self.role = role
        self.email = email

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(10), default='user')
    status = db.Column(db.String(20), default='active')
    usd_balance = db.Column(db.Float, default=1000.0)
    lbp_balance = db.Column(db.Float, default=10000000.0)
    email = db.Column(db.String(100), nullable=True)
    mfa_enabled = db.Column(db.Boolean, default=False)
    mfa_code = db.Column(db.String(10), nullable=True)
    mfa_code_expiry = db.Column(db.DateTime, nullable=True)


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        fields = ("id", "user_name", "role", "status", "usd_balance", "lbp_balance", "email", "mfa_enabled")

user_schema = UserSchema()
