import os
import hmac
from datetime import datetime, timezone
from flask import Flask, jsonify, request, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'local-development-only-change-me')
raw_db_url = os.environ.get('DATABASE_URL', 'sqlite:///qarargah_demo.db')
if raw_db_url.startswith('postgres://'):
    raw_db_url = raw_db_url.replace('postgres://', 'postgresql://', 1)
if raw_db_url.startswith('postgresql://') and 'sslmode=' not in raw_db_url:
    raw_db_url += ('&' if '?' in raw_db_url else '?') + 'sslmode=require'
app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('COOKIE_SECURE', 'true').lower() == 'true'
db = SQLAlchemy(app)

class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(40), nullable=False, index=True)
    title = db.Column(db.String(240), nullable=False)
    payload = db.Column(db.JSON, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

with app.app_context():
    db.create_all()

@app.get('/')
def home():
    return send_from_directory('.', 'index.html')

@app.get('/api/health')
def health():
    try:
        db.session.execute(text('SELECT 1'))
        return jsonify(status='ok', database='connected')
    except Exception:
        app.logger.exception('Database health check failed')
        return jsonify(status='error', database='unavailable'), 503

@app.get('/api/me')
def me():
    return jsonify(authenticated=bool(session.get('demo_logged_in')))

@app.post('/api/login')
def login():
    data = request.get_json(silent=True) or {}
    expected_user = os.environ.get('ADMIN_USERNAME', 'demo-admin')
    expected_password = os.environ.get('ADMIN_PASSWORD', '')
    username = str(data.get('username', ''))
    password = str(data.get('password', ''))
    if not expected_password:
        return jsonify(error='مدیر سامانه هنوز رمز عبور آزمایشی را در تنظیمات Render تعیین نکرده است.'), 503
    if hmac.compare_digest(username, expected_user) and hmac.compare_digest(password, expected_password):
        session.clear()
        session['demo_logged_in'] = True
        return jsonify(ok=True)
    return jsonify(error='نام کاربری یا رمز عبور نادرست است.'), 401

@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify(ok=True)

def require_login():
    if not session.get('demo_logged_in'):
        return jsonify(error='ابتدا وارد سامانه شوید.'), 401
    # Same-origin browser requests only; helps block cross-site form submissions.
    origin = request.headers.get('Origin')
    if origin and origin.rstrip('/') != request.host_url.rstrip('/'):
        return jsonify(error='درخواست از مبدأ نامعتبر پذیرفته نشد.'), 403
    return None

def record_json(record):
    return {
        'id': record.id,
        'category': record.category,
        'title': record.title,
        'payload': record.payload,
        'created_at': record.created_at.isoformat() if record.created_at else None,
        'updated_at': record.updated_at.isoformat() if record.updated_at else None,
    }

@app.get('/api/records')
def list_records():
    denied = require_login()
    if denied: return denied
    query = Record.query.order_by(Record.created_at.desc())
    category = request.args.get('category')
    if category: query = query.filter_by(category=category)
    return jsonify(records=[record_json(r) for r in query.limit(150).all()])

@app.post('/api/records')
def create_record():
    denied = require_login()
    if denied: return denied
    data = request.get_json(silent=True) or {}
    category = str(data.get('category', '')).strip()
    payload = data.get('payload')
    if category not in {'employment', 'relief', 'meetings', 'exhibitions', 'bottlenecks', 'continuity'} or not isinstance(payload, dict):
        return jsonify(error='اطلاعات ارسالی معتبر نیست.'), 400
    title = str(data.get('title') or category).strip()[:240]
    record = Record(category=category, title=title, payload=payload)
    db.session.add(record)
    db.session.commit()
    return jsonify(record=record_json(record)), 201

@app.put('/api/records/<int:record_id>')
def update_record(record_id):
    denied = require_login()
    if denied: return denied
    record = db.session.get(Record, record_id)
    if not record: return jsonify(error='گزارش پیدا نشد.'), 404
    data = request.get_json(silent=True) or {}
    payload = data.get('payload')
    if not isinstance(payload, dict): return jsonify(error='اطلاعات ارسالی معتبر نیست.'), 400
    record.payload = payload
    record.title = str(data.get('title') or record.category).strip()[:240]
    db.session.commit()
    return jsonify(record=record_json(record))

@app.delete('/api/records/<int:record_id>')
def delete_record(record_id):
    denied = require_login()
    if denied: return denied
    record = db.session.get(Record, record_id)
    if not record: return jsonify(error='گزارش پیدا نشد.'), 404
    db.session.delete(record)
    db.session.commit()
    return jsonify(ok=True)

@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith('/api/'):
        return jsonify(error='مسیر موردنظر پیدا نشد.'), 404
    return 'صفحه پیدا نشد', 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
