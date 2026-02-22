from flask import Flask, request, jsonify, abort, make_response
import os
import csv
import io
import json
import random
import statistics
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

    # MFA flow: generate code and require second step
    if user.mfa_enabled:
        code = str(random.randint(100000, 999999))
        user.mfa_code = code
        user.mfa_code_expiry = datetime.datetime.now() + datetime.timedelta(minutes=10)
        db.session.commit()
        # deliver code via notification (in production, this would be email/SMS)
        notif = Notification(user_id=user.id, message=f"Your MFA code is: {code}")
        db.session.add(notif)
        db.session.commit()
        return jsonify({"mfa_required": True, "user_id": user.id})

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

    usd_to_lbp_val = request.json["usd_to_lbp"]
    rate = lbp_amount / usd_amount if usd_amount else 0

    t = Transaction(
        usd_amount=usd_amount,
        lbp_amount=lbp_amount,
        usd_to_lbp=usd_to_lbp_val,
        user_id=user_id
    )
    db.session.add(t)
    db.session.flush()

    # auto-flag outliers after there are enough data points
    if is_outlier_rate(rate, usd_to_lbp_val):
        t.flagged = True

    db.session.commit()

    current_rate = get_current_rate(usd_to_lbp_val)
    if current_rate:
        check_alerts_for_rate(current_rate, usd_to_lbp_val)

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


# ── analytics & history ───────────────────────────────────────────────────────

@app.route('/exchangeRate/history', methods=['GET'])
@limiter.limit("10 per minute")
def exchange_rate_history():
    """Return time-series exchange rate grouped by hour or day."""
    hours = int(request.args.get("hours", 72))
    interval = request.args.get("interval", "hourly")  # hourly | daily

    now = datetime.datetime.now()
    start = now - datetime.timedelta(hours=hours)

    txs = Transaction.query.filter(
        Transaction.added_date.between(start, now),
        Transaction.flagged == False
    ).order_by(Transaction.added_date).all()

    buckets = {}
    for t in txs:
        if interval == "daily":
            key = t.added_date.strftime("%Y-%m-%d")
        else:
            key = t.added_date.strftime("%Y-%m-%dT%H:00")

        if key not in buckets:
            buckets[key] = {"usd_to_lbp": [], "lbp_to_usd": []}
        rate = t.lbp_amount / t.usd_amount if t.usd_amount else None
        if rate:
            if t.usd_to_lbp:
                buckets[key]["usd_to_lbp"].append(rate)
            else:
                buckets[key]["lbp_to_usd"].append(rate)

    result = []
    for ts in sorted(buckets.keys()):
        u = buckets[ts]["usd_to_lbp"]
        l = buckets[ts]["lbp_to_usd"]
        result.append({
            "timestamp": ts,
            "usd_to_lbp": sum(u) / len(u) if u else None,
            "lbp_to_usd": sum(l) / len(l) if l else None
        })

    return jsonify(result)


@app.route('/transaction/stats', methods=['GET'])
@limiter.limit("10 per minute")
def transaction_stats():
    """Return basic statistics for the authenticated user's transactions."""
    user = require_auth(request)

    txs = Transaction.query.filter_by(user_id=user.id).all()
    if not txs:
        return jsonify({"count": 0})

    rates = [(t.lbp_amount / t.usd_amount) for t in txs if t.usd_amount]
    count = len(rates)
    avg = sum(rates) / count
    mn = min(rates)
    mx = max(rates)

    return jsonify({
        "count": count,
        "avg_rate": avg,
        "min_rate": mn,
        "max_rate": mx
    })


# ── P2P marketplace ───────────────────────────────────────────────────────────

@app.route('/offer', methods=['POST'])
@limiter.limit("10 per minute")
def create_offer():
    user = require_auth(request)
    data = request.get_json() or {}

    usd_amount = float(data.get("usd_amount", 0))
    lbp_amount = float(data.get("lbp_amount", 0))
    usd_to_lbp = data.get("usd_to_lbp")

    if usd_amount <= 0 or lbp_amount <= 0 or usd_to_lbp is None:
        return jsonify({"error": "usd_amount, lbp_amount, and usd_to_lbp are required"}), 400

    # lock funds
    if usd_to_lbp:
        if user.usd_balance < usd_amount:
            return jsonify({"error": "Insufficient USD balance"}), 400
        user.usd_balance -= usd_amount
    else:
        if user.lbp_balance < lbp_amount:
            return jsonify({"error": "Insufficient LBP balance"}), 400
        user.lbp_balance -= lbp_amount

    offer = Offer(user_id=user.id, usd_amount=usd_amount, lbp_amount=lbp_amount, usd_to_lbp=usd_to_lbp)
    db.session.add(offer)
    db.session.commit()
    return jsonify(offer_schema.dump(offer)), 201


@app.route('/offer', methods=['GET'])
@limiter.limit("10 per minute")
def list_offers():
    open_offers = Offer.query.filter_by(status='open').all()
    return jsonify(offers_schema.dump(open_offers))


@app.route('/offer/<int:offer_id>/accept', methods=['POST'])
@limiter.limit("10 per minute")
def accept_offer(offer_id):
    user = require_auth(request)
    offer = Offer.query.get_or_404(offer_id)

    if offer.status != 'open':
        return jsonify({"error": "Offer is no longer available"}), 409
    if offer.user_id == user.id:
        return jsonify({"error": "Cannot accept your own offer"}), 400

    if offer.usd_to_lbp:
        if user.lbp_balance < offer.lbp_amount:
            return jsonify({"error": "Insufficient LBP balance"}), 400
        user.lbp_balance -= offer.lbp_amount
        user.usd_balance += offer.usd_amount
        creator = User.query.get(offer.user_id)
        creator.lbp_balance += offer.lbp_amount
    else:
        if user.usd_balance < offer.usd_amount:
            return jsonify({"error": "Insufficient USD balance"}), 400
        user.usd_balance -= offer.usd_amount
        user.lbp_balance += offer.lbp_amount
        creator = User.query.get(offer.user_id)
        creator.usd_balance += offer.usd_amount

    offer.status = 'accepted'
    offer.accepted_by = user.id
    offer.accepted_at = datetime.datetime.now()
    db.session.commit()
    return jsonify(offer_schema.dump(offer))


@app.route('/offer/<int:offer_id>', methods=['DELETE'])
@limiter.limit("10 per minute")
def cancel_offer(offer_id):
    user = require_auth(request)
    offer = Offer.query.get_or_404(offer_id)

    if offer.user_id != user.id:
        abort(403)
    if offer.status != 'open':
        return jsonify({"error": "Offer is not open"}), 409

    if offer.usd_to_lbp:
        user.usd_balance += offer.usd_amount
    else:
        user.lbp_balance += offer.lbp_amount

    offer.status = 'cancelled'
    db.session.commit()
    return jsonify(offer_schema.dump(offer))


# ── alerts & watchlist ────────────────────────────────────────────────────────

def get_current_rate(usd_to_lbp):
    """Return the 72-hour average exchange rate (excluding flagged)."""
    now = datetime.datetime.now()
    start = now - datetime.timedelta(hours=72)
    txs = Transaction.query.filter(
        Transaction.added_date.between(start, now),
        Transaction.usd_to_lbp == usd_to_lbp,
        Transaction.flagged == False
    ).all()
    if not txs:
        return None
    total_usd = sum(t.usd_amount for t in txs)
    total_lbp = sum(t.lbp_amount for t in txs)
    if usd_to_lbp:
        return total_lbp / total_usd if total_usd else None
    else:
        return total_usd / total_lbp if total_lbp else None


def check_alerts_for_rate(rate, usd_to_lbp):
    """Trigger any active alerts whose threshold has been crossed."""
    active_alerts = Alert.query.filter_by(usd_to_lbp=usd_to_lbp, active=True).all()
    for alert in active_alerts:
        if rate >= alert.target_rate:
            alert.active = False
            notif = Notification(
                user_id=alert.user_id,
                message=f"Alert triggered: rate {rate:.2f} reached your target {alert.target_rate:.2f}"
            )
            db.session.add(notif)
    db.session.commit()


@app.route('/alert', methods=['POST'])
@limiter.limit("10 per minute")
def create_alert():
    user = require_auth(request)
    data = request.get_json() or {}

    target_rate = data.get("target_rate")
    usd_to_lbp = data.get("usd_to_lbp")

    if target_rate is None or usd_to_lbp is None:
        return jsonify({"error": "target_rate and usd_to_lbp are required"}), 400

    alert = Alert(user_id=user.id, target_rate=float(target_rate), usd_to_lbp=usd_to_lbp)
    db.session.add(alert)
    db.session.commit()
    return jsonify(alert_schema.dump(alert)), 201


@app.route('/alert', methods=['GET'])
@limiter.limit("10 per minute")
def list_alerts():
    user = require_auth(request)
    user_alerts = Alert.query.filter_by(user_id=user.id).all()
    return jsonify(alerts_schema.dump(user_alerts))


@app.route('/alert/<int:alert_id>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_alert(alert_id):
    user = require_auth(request)
    alert = Alert.query.get_or_404(alert_id)
    if alert.user_id != user.id:
        abort(403)
    db.session.delete(alert)
    db.session.commit()
    return jsonify({"message": "Alert deleted"})


@app.route('/watchlist', methods=['POST'])
@limiter.limit("10 per minute")
def add_watchlist():
    user = require_auth(request)
    data = request.get_json() or {}

    label = data.get("label")
    rate_threshold = data.get("rate_threshold")
    usd_to_lbp = data.get("usd_to_lbp")

    if not label or rate_threshold is None or usd_to_lbp is None:
        return jsonify({"error": "label, rate_threshold, and usd_to_lbp are required"}), 400

    item = WatchlistItem(user_id=user.id, label=label, rate_threshold=float(rate_threshold), usd_to_lbp=usd_to_lbp)
    db.session.add(item)
    db.session.commit()
    return jsonify(watchlist_schema.dump(item)), 201


@app.route('/watchlist', methods=['GET'])
@limiter.limit("10 per minute")
def list_watchlist():
    user = require_auth(request)
    items = WatchlistItem.query.filter_by(user_id=user.id).all()
    return jsonify(watchlists_schema.dump(items))


@app.route('/watchlist/<int:item_id>', methods=['DELETE'])
@limiter.limit("10 per minute")
def delete_watchlist(item_id):
    user = require_auth(request)
    item = WatchlistItem.query.get_or_404(item_id)
    if item.user_id != user.id:
        abort(403)
    db.session.delete(item)
    db.session.commit()
    return jsonify({"message": "Watchlist item removed"})


# ── CSV export & preferences ──────────────────────────────────────────────────

@app.route('/transaction/export', methods=['GET'])
@limiter.limit("10 per minute")
def export_transactions():
    user = require_auth(request)
    txs = Transaction.query.filter_by(user_id=user.id).order_by(Transaction.added_date).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "usd_amount", "lbp_amount", "usd_to_lbp", "added_date", "source", "flagged"])
    for t in txs:
        writer.writerow([t.id, t.usd_amount, t.lbp_amount, t.usd_to_lbp, t.added_date, t.source, t.flagged])

    resp = make_response(output.getvalue())
    resp.headers["Content-Disposition"] = "attachment; filename=transactions.csv"
    resp.headers["Content-Type"] = "text/csv"
    return resp


@app.route('/preferences', methods=['GET'])
@limiter.limit("10 per minute")
def get_preferences():
    user = require_auth(request)
    prefs = UserPreferences.query.filter_by(user_id=user.id).first()
    if not prefs:
        prefs = UserPreferences(user_id=user.id)
        db.session.add(prefs)
        db.session.commit()
    return jsonify(preferences_schema.dump(prefs))


@app.route('/preferences', methods=['PUT'])
@limiter.limit("10 per minute")
def update_preferences():
    user = require_auth(request)
    data = request.get_json() or {}

    prefs = UserPreferences.query.filter_by(user_id=user.id).first()
    if not prefs:
        prefs = UserPreferences(user_id=user.id)
        db.session.add(prefs)

    if "default_time_range" in data:
        prefs.default_time_range = int(data["default_time_range"])
    if "default_interval" in data:
        if data["default_interval"] not in ("hourly", "daily"):
            return jsonify({"error": "default_interval must be 'hourly' or 'daily'"}), 400
        prefs.default_interval = data["default_interval"]

    db.session.commit()
    return jsonify(preferences_schema.dump(prefs))


# ── admin RBAC & audit logging ────────────────────────────────────────────────

def require_admin(req):
    user = require_auth(req)
    if user.role != 'admin':
        abort(403)
    return user


def log_event(event_type, description, user_id=None):
    entry = AuditLog(event_type=event_type, description=description, user_id=user_id)
    db.session.add(entry)
    db.session.commit()


@app.route('/admin/users', methods=['GET'])
@limiter.limit("10 per minute")
def admin_list_users():
    require_admin(request)
    from model.user import UserSchema
    users = User.query.all()
    return jsonify(UserSchema(many=True).dump(users))


@app.route('/admin/user/<int:user_id>/status', methods=['PUT'])
@limiter.limit("10 per minute")
def admin_set_user_status(user_id):
    admin = require_admin(request)
    data = request.get_json() or {}
    new_status = data.get("status")

    if new_status not in ("active", "suspended"):
        return jsonify({"error": "status must be 'active' or 'suspended'"}), 400

    target = User.query.get_or_404(user_id)
    target.status = new_status
    db.session.commit()
    log_event("user_status_change", f"User {target.user_name} set to {new_status}", user_id=admin.id)
    return jsonify({"id": target.id, "user_name": target.user_name, "status": target.status})


@app.route('/admin/audit-log', methods=['GET'])
@limiter.limit("10 per minute")
def admin_audit_log():
    require_admin(request)
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(200).all()
    return jsonify(audit_logs_schema.dump(logs))


@app.route('/admin/user/<int:user_id>/role', methods=['PUT'])
@limiter.limit("10 per minute")
def admin_set_user_role(user_id):
    admin = require_admin(request)
    data = request.get_json() or {}
    new_role = data.get("role")

    if new_role not in ("user", "admin"):
        return jsonify({"error": "role must be 'user' or 'admin'"}), 400

    target = User.query.get_or_404(user_id)
    target.role = new_role
    db.session.commit()
    log_event("role_change", f"User {target.user_name} role changed to {new_role}", user_id=admin.id)
    return jsonify({"id": target.id, "user_name": target.user_name, "role": target.role})


# ── notifications & data quality ─────────────────────────────────────────────

def is_outlier_rate(rate, usd_to_lbp):
    """Return True if rate deviates more than 2 std deviations from the 72hr mean."""
    now = datetime.datetime.now()
    start = now - datetime.timedelta(hours=72)
    txs = Transaction.query.filter(
        Transaction.added_date.between(start, now),
        Transaction.usd_to_lbp == usd_to_lbp,
        Transaction.flagged == False
    ).all()
    if len(txs) < 5:
        return False
    rates = [t.lbp_amount / t.usd_amount for t in txs if t.usd_amount]
    if len(rates) < 5:
        return False
    mean = statistics.mean(rates)
    stdev = statistics.stdev(rates)
    return abs(rate - mean) > 2 * stdev


def send_notification(user_id, message):
    notif = Notification(user_id=user_id, message=message)
    db.session.add(notif)
    db.session.commit()


@app.route('/notification', methods=['GET'])
@limiter.limit("10 per minute")
def list_notifications():
    user = require_auth(request)
    notifs = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).all()
    return jsonify(notifications_schema.dump(notifs))


@app.route('/notification/<int:notif_id>/read', methods=['PUT'])
@limiter.limit("10 per minute")
def mark_notification_read(notif_id):
    user = require_auth(request)
    notif = Notification.query.get_or_404(notif_id)
    if notif.user_id != user.id:
        abort(403)
    notif.read = True
    db.session.commit()
    return jsonify(notification_schema.dump(notif))


@app.route('/admin/transaction/<int:tx_id>/flag', methods=['PUT'])
@limiter.limit("10 per minute")
def admin_flag_transaction(tx_id):
    admin = require_admin(request)
    data = request.get_json() or {}
    flagged = data.get("flagged", True)

    tx = Transaction.query.get_or_404(tx_id)
    tx.flagged = bool(flagged)
    db.session.commit()
    log_event("transaction_flag", f"Transaction {tx_id} flagged={flagged}", user_id=admin.id)
    return jsonify(transaction_schema.dump(tx))


# ── reporting & backup ────────────────────────────────────────────────────────

@app.route('/report/summary', methods=['GET'])
@limiter.limit("10 per minute")
def report_summary():
    require_auth(request)

    now = datetime.datetime.now()
    start_72h = now - datetime.timedelta(hours=72)

    total_tx = Transaction.query.count()
    recent_tx = Transaction.query.filter(Transaction.added_date >= start_72h).count()
    flagged_tx = Transaction.query.filter_by(flagged=True).count()
    total_users = User.query.count()
    active_users = User.query.filter_by(status='active').count()
    open_offers = Offer.query.filter_by(status='open').count()

    usd_to_lbp_rate = get_current_rate(True)
    lbp_to_usd_rate = get_current_rate(False)

    return jsonify({
        "total_transactions": total_tx,
        "transactions_last_72h": recent_tx,
        "flagged_transactions": flagged_tx,
        "total_users": total_users,
        "active_users": active_users,
        "open_offers": open_offers,
        "current_usd_to_lbp": usd_to_lbp_rate,
        "current_lbp_to_usd": lbp_to_usd_rate
    })


@app.route('/admin/backup', methods=['POST'])
@limiter.limit("5 per minute")
def create_backup():
    admin = require_admin(request)

    os.makedirs("backups", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"backups/backup_{timestamp}.json"

    txs = Transaction.query.all()
    users = User.query.all()

    from model.transaction import TransactionSchema as TxSchema
    from model.user import UserSchema as USchema

    data = {
        "timestamp": timestamp,
        "transactions": TxSchema(many=True).dump(txs),
        "users": USchema(many=True).dump(users)
    }

    with open(filename, "w") as f:
        json.dump(data, f, indent=2, default=str)

    log_event("backup", f"Backup created: {filename}", user_id=admin.id)
    return jsonify({"message": "Backup created", "file": filename})


# ── MFA (multi-factor authentication) ────────────────────────────────────────

@app.route('/authentication/mfa', methods=['POST'])
@limiter.limit("5 per minute")
def verify_mfa():
    data = request.get_json() or {}
    user_id = data.get("user_id")
    code = data.get("code")

    if not user_id or not code:
        return jsonify({"error": "user_id and code are required"}), 400

    user = User.query.get(user_id)
    if not user or not user.mfa_enabled:
        abort(403)

    if not user.mfa_code or not user.mfa_code_expiry:
        return jsonify({"error": "No MFA code pending"}), 400

    if datetime.datetime.now() > user.mfa_code_expiry:
        user.mfa_code = None
        user.mfa_code_expiry = None
        db.session.commit()
        return jsonify({"error": "MFA code expired"}), 401

    if user.mfa_code != str(code):
        return jsonify({"error": "Invalid MFA code"}), 401

    user.mfa_code = None
    user.mfa_code_expiry = None
    db.session.commit()
    token = create_token(user.id)
    return jsonify({"token": token})


@app.route('/user/mfa', methods=['PUT'])
@limiter.limit("10 per minute")
def toggle_mfa():
    user = require_auth(request)
    data = request.get_json() or {}
    enabled = data.get("enabled")

    if enabled is None:
        return jsonify({"error": "enabled field is required"}), 400

    user.mfa_enabled = bool(enabled)
    if not user.mfa_enabled:
        user.mfa_code = None
        user.mfa_code_expiry = None
    db.session.commit()
    return jsonify({"mfa_enabled": user.mfa_enabled})


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False)
