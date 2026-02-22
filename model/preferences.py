from extensions import db, ma

class UserPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    default_time_range = db.Column(db.Integer, default=72)
    default_interval = db.Column(db.String(20), default='hourly')

    def __init__(self, user_id, default_time_range=72, default_interval='hourly'):
        super().__init__(
            user_id=user_id,
            default_time_range=default_time_range,
            default_interval=default_interval
        )


class PreferencesSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = UserPreferences
        include_fk = True
        fields = ("id", "user_id", "default_time_range", "default_interval")

preferences_schema = PreferencesSchema()
