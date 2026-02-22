from flask import Flask, request, jsonify, abort
import os
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

import jwt
import datetime

#initialize from here to avoid circular import issues
from extensions import db, bcrypt, ma

from db_config import DB_CONFIG
from model.user import User, user_schema
from model.transaction import Transaction, transaction_schema, TransactionSchema
from model.offer import Offer, offer_schema, offers_schema
from model.alert import Alert, alert_schema, alerts_schema
from model.watchlist import WatchlistItem, watchlist_schema, watchlists_schema
from model.preferences import UserPreferences, preferences_schema
from model.audit_log import AuditLog, audit_log_schema, audit_logs_schema
from model.notification import Notification, notification_schema, notifications_schema

# Load environment variables from the .env file
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
SECRET_KEY_Bcrypt = os.getenv("SECRET_KEY_Bcrypt")

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = DB_CONFIG
#Secret key used for security, it is a 32 hex key
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
# we use init_app because we initialized in extensions.py
db.init_app(app)
bcrypt.init_app(app)
ma.init_app(app)

limiter = Limiter(key_func=get_remote_address, app=app)


# ── helpers ──────────────────────────────────────────────────────────────────

def extract_auth_token(req):
    auth_header = req.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def decode_token(token):
    payload = jwt.decode(token, SECRET_KEY_Bcrypt, algorithms=["HS256"])
    return int(payload["sub"])


def create_token(user_id):
    payload = {
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=4),
        'iat': datetime.datetime.utcnow(),
        'sub': str(user_id)
    }
    return jwt.encode(payload, SECRET_KEY_Bcrypt, algorithm='HS256')


def require_auth(req):
    token = extract_auth_token(req)
    if not token:
        abort(401)
    try:
        user_id = decode_token(token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        abort(403)
    user = User.query.get(user_id)
    if not user:
        abort(403)
    return user


# ── user registration & auth ──────────────────────────────────────────────────

@app.route('/user', methods=['POST'])
@limiter.limit("10 per minute")
def create_user():
    data = request.get_json() or {}
    user_name = data.get("user_name")
    password = data.get("password")

    if not user_name or not password:
        return jsonify({"error": "user_name and password are required"}), 400

    if User.query.filter_by(user_name=user_name).first():
        return jsonify({"error": "user_name already exists"}), 409

    u = User(user_name=user_name, password=password, email=data.get("email"))
    db.session.add(u)
    db.session.commit()
    return jsonify(user_schema.dump(u)), 201


@app.route('/authentication', methods=['POST'])
@limiter.limit("5 per minute")
def authenticate():
    data = request.get_json() or {}
    user_name = data.get("user_name")
    password = data.get("password")

    if not user_name or not password:
        abort(400)

    user = User.query.filter_by(user_name=user_name).first()
    if not user:
        abort(403)

    if not bcrypt.check_password_hash(user.hashed_password, password):
        abort(403)

    token = create_token(user.id)
    return jsonify({"token": token})


# ── transactions ──────────────────────────────────────────────────────────────

@app.route('/transaction', methods=['POST'])
@limiter.limit("10 per minute")
def add_transaction():
    if "usd_to_lbp" not in request.get_json():
        return jsonify({"error": "usd_to_lbp is required"}), 400

    usd_amount = float(request.json.get("usd_amount", 0))
    if usd_amount <= 0:
        return jsonify({"error": "Invalid usd_amount"}), 400

    lbp_amount = float(request.json.get("lbp_amount", 0))
    if lbp_amount <= 0:
        return jsonify({"error": "Invalid lbp_amount"}), 400

    token = extract_auth_token(request)
    user_id = None
    if token:
        try:
            user_id = decode_token(token)
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            abort(403)

    t = Transaction(
        usd_amount=usd_amount,
        lbp_amount=lbp_amount,
        usd_to_lbp=request.json["usd_to_lbp"],
        user_id=user_id
    )
    db.session.add(t)
    db.session.commit()
    return jsonify(transaction_schema.dump(t))


@app.route('/transaction', methods=['GET'])
@limiter.limit("10 per minute")
def get_transactions():
    token = extract_auth_token(request)
    if not token:
        abort(403)
    try:
        user_id = decode_token(token)
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        abort(403)

    txs = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify(TransactionSchema(many=True).dump(txs))


@app.route('/exchangeRate', methods=['GET'])
@limiter.limit("10 per minute")
def exchange_rate():
    now = datetime.datetime.now()
    start = now - datetime.timedelta(hours=72)
    usd_to_lbp_tx = Transaction.query.filter(
        Transaction.added_date.between(start, now),
        Transaction.usd_to_lbp == True,
        Transaction.flagged == False
    ).all()
    lbp_to_usd_tx = Transaction.query.filter(
        Transaction.added_date.between(start, now),
        Transaction.usd_to_lbp == False,
        Transaction.flagged == False
    ).all()

    if len(usd_to_lbp_tx) == 0:
        avg_usd_to_lbp = None
    else:
        total_usd = sum(t.usd_amount for t in usd_to_lbp_tx)
        total_lbp = sum(t.lbp_amount for t in usd_to_lbp_tx)
        avg_usd_to_lbp = (total_lbp / total_usd) if total_usd != 0 else None

    if len(lbp_to_usd_tx) == 0:
        avg_lbp_to_usd = None
    else:
        total_lbp = sum(t.lbp_amount for t in lbp_to_usd_tx)
        total_usd = sum(t.usd_amount for t in lbp_to_usd_tx)
        avg_lbp_to_usd = (total_usd / total_lbp) if total_lbp != 0 else None

    return jsonify({
        "usd_to_lbp": avg_usd_to_lbp,
        "lbp_to_usd": avg_lbp_to_usd
    })


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)
