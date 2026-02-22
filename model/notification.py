from datetime import datetime
from extensions import db, ma

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)

    def __init__(self, user_id, message):
        super().__init__(
            user_id=user_id,
            message=message,
            read=False,
            created_at=datetime.now()
        )


class NotificationSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Notification
        include_fk = True
        fields = ("id", "user_id", "message", "read", "created_at")

notification_schema = NotificationSchema()
notifications_schema = NotificationSchema(many=True)
