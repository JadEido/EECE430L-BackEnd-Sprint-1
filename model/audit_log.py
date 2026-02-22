from datetime import datetime
from extensions import db, ma

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    event_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime)

    def __init__(self, event_type, description, user_id=None):
        super().__init__(
            event_type=event_type,
            description=description,
            user_id=user_id,
            timestamp=datetime.now()
        )


class AuditLogSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = AuditLog
        include_fk = True
        fields = ("id", "user_id", "event_type", "description", "timestamp")

audit_log_schema = AuditLogSchema()
audit_logs_schema = AuditLogSchema(many=True)
