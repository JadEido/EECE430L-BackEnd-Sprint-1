from datetime import datetime
from extensions import db, ma

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target_rate = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime)

    def __init__(self, user_id, target_rate, usd_to_lbp):
        super().__init__(
            user_id=user_id,
            target_rate=target_rate,
            usd_to_lbp=usd_to_lbp,
            active=True,
            created_at=datetime.now()
        )


class AlertSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Alert
        include_fk = True
        fields = ("id", "user_id", "target_rate", "usd_to_lbp", "active", "created_at")

alert_schema = AlertSchema()
alerts_schema = AlertSchema(many=True)
