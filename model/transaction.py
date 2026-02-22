#import from here to avoid circular import issues
from datetime import datetime
from extensions import db, ma

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usd_amount = db.Column(db.Float, nullable=False)
    lbp_amount = db.Column(db.Float, nullable=False)
    usd_to_lbp = db.Column(db.Boolean, nullable=False)

    added_date = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    def __init__(self, usd_amount, lbp_amount, usd_to_lbp, user_id=None):
        super(Transaction, self).__init__(
            usd_amount=usd_amount,
            lbp_amount=lbp_amount,
            usd_to_lbp=usd_to_lbp,
            user_id=user_id,
            added_date=datetime.now()
        )


class TransactionSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Transaction
        include_fk = True
        fields = ("id", "usd_amount", "lbp_amount", "usd_to_lbp", "added_date", "user_id")

transaction_schema = TransactionSchema()