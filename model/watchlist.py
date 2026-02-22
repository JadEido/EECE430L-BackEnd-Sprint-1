from datetime import datetime
from extensions import db, ma

class WatchlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    label = db.Column(db.String(50), nullable=False)
    rate_threshold = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)
    created_at = db.Column(db.DateTime)

    def __init__(self, user_id, label, rate_threshold, usd_to_lbp):
        super().__init__(
            user_id=user_id,
            label=label,
            rate_threshold=rate_threshold,
            usd_to_lbp=usd_to_lbp,
            created_at=datetime.now()
        )


class WatchlistSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = WatchlistItem
        include_fk = True
        fields = ("id", "user_id", "label", "rate_threshold", "usd_to_lbp", "created_at")

watchlist_schema = WatchlistSchema()
watchlists_schema = WatchlistSchema(many=True)
