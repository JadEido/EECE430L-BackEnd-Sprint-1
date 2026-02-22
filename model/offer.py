from datetime import datetime
from extensions import db, ma

class Offer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime)
    accepted_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    accepted_at = db.Column(db.DateTime, nullable=True)

    def __init__(self, user_id, usd_amount, lbp_amount, usd_to_lbp):
        super().__init__(
            user_id=user_id,
            usd_amount=usd_amount,
            lbp_amount=lbp_amount,
            usd_to_lbp=usd_to_lbp,
            status='open',
            created_at=datetime.now()
        )


class OfferSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Offer
        include_fk = True
        fields = ("id", "user_id", "usd_amount", "lbp_amount", "usd_to_lbp", "status", "created_at", "accepted_by", "accepted_at")

offer_schema = OfferSchema()
offers_schema = OfferSchema(many=True)
