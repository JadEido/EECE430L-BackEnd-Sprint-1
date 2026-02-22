#import from here to avoid circular import issues
from extensions import db, bcrypt, ma

class User(db.Model):
    def __init__(self, user_name, password):
        self.user_name = user_name
        self.hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

    id = db.Column(db.Integer, primary_key=True)
    user_name = db.Column(db.String(30), unique=True, nullable=False)
    hashed_password = db.Column(db.String(128), nullable=False)


class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        fields = ("id", "user_name")
        model = User

user_schema = UserSchema()

