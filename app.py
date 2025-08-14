
import os
from datetime import datetime
from uuid import uuid4
from decimal import Decimal, ROUND_HALF_UP
from flask import Flask, request, session, redirect, url_for, render_template_string, flash
from flask_sqlalchemy import SQLAlchemy

# ------------------ Config ------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

MAX_GAS_USD = Decimal(os.getenv("MAX_GAS_USD", "5"))
MAX_GAS_PCT = Decimal(os.getenv("MAX_GAS_PCT", "1.5"))
DEFAULT_CHAIN = os.getenv("DEFAULT_CHAIN", "TRC20")
DEFAULT_PAYOUT_METHOD = os.getenv("DEFAULT_PAYOUT_METHOD", "CRYPTO")  # CRYPTO or BANK

# Protocols & required auth-code length (F38)
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

app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------ Models ------------------
class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mid = db.Column(db.String(64), unique=True, index=True)
    payout_method = db.Column(db.String(16), default=DEFAULT_PAYOUT_METHOD)  # CRYPTO or BANK
    chain = db.Column(db.String(16), default=DEFAULT_CHAIN)  # crypto
    address = db.Column(db.String(128))
    bank_name = db.Column(db.String(64))  # bank
    account_name = db.Column(db.String(64))
    account_no = db.Column(db.String(64))
    ifsc_swift = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mti = db.Column(db.String(4), default="0210")
    protocol = db.Column(db.String(64))
    rrn = db.Column(db.String(24))
    stan = db.Column(db.String(12))
    tid = db.Column(db.String(16))
    mid = db.Column(db.String(32))
    amount_cents = db.Column(db.Integer, default=0)
    currency = db.Column(db.String(3), default="USD")
    resp_code = db.Column(db.String(2), default="00")
    auth_code = db.Column(db.String(12))  # F38
    status = db.Column(db.String(32), default="approved")
    payout_method = db.Column(db.String(16), default=DEFAULT_PAYOUT_METHOD)
    payout_chain = db.Column(db.String(16), default=DEFAULT_CHAIN)
    payout_address = db.Column(db.String(128))
    payout_bank_ref = db.Column(db.String(64))
    tx_hash = db.Column(db.String(128))
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# ------------------ Helpers ------------------
NAV = """
<nav>
  <a href='{{ url_for("home") }}'>Home</a> |
  <a href='{{ url_for("monitor") }}'>History</a> |
  <a href='{{ url_for("merchants") }}'>Merchants</a> |
  {% if "user" in session %}<a href='{{ url_for("logout") }}'>Logout</a>{% endif %}
</nav>
"""

BASE = """
<!doctype html><html><head><meta charset='utf-8'><title>{{ title }}</title></head><body>
""" + NAV + """
<div>
{% with msgs = get_flashed_messages() %}
  {% if msgs %}<ul style='color:green'>{% for m in msgs %}<li>{{ m }}</li>{% endfor %}</ul>{% endif %}
{% endwith %}
{% block content %}{% endblock %}
</div></body></html>
"""

def require_login():
    return bool(session.get("user"))

def dollars_to_cents(amount_str):
    try:
        amt = Decimal(amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return int(amt * 100)
    except:
        return 0

def cents_to_display(cents):
    return f"{Decimal(cents)/100:.2f}"

def compute_gas_caps(amount_cents):
    amount_usd = Decimal(amount_cents) / 100
    pct_cap = (amount_usd * (MAX_GAS_PCT / 100)).quantize(Decimal("0.01"))
    return min(pct_cap, MAX_GAS_USD)

def simulate_network_fee_usd(chain, amount_cents):
    base = Decimal("0.20") if chain.upper() == "TRC20" else Decimal("2.50")
    bump = (Decimal(amount_cents) / 10000) * Decimal("0.03")
    return (base + bump).quantize(Decimal("0.01"))

def simulate_send_crypto(chain, to_addr, amount_cents):
    fee_usd = simulate_network_fee_usd(chain, amount_cents)
    txh = "0x" + uuid4().hex
    return txh, fee_usd

def simulate_bank_transfer(mid, amount_cents, currency):
    bank_ref = "BNK-" + uuid4().hex[:10].upper()
    fee_usd = Decimal("0.50")
    return bank_ref, fee_usd

def validate_auth_code(protocol, auth_code):
    need = PROTOCOLS.get(protocol)
    return bool(auth_code) and need is not None and len(auth_code.strip()) == int(need)

# ------------------ Routes ------------------
@app.route("/", methods=["GET"])
def root():
    return redirect(url_for("home") if session.get("user") else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        if request.form.get("password") == ADMIN_PASSWORD:
            session["user"] = "admin"
            return redirect(url_for("home"))
        flash("Invalid password")
    return render_template_string(BASE + """
    {% block content %}
    <h3>Login</h3>
    <form method='post'><input type='password' name='password'><button>Login</button></form>
    {% endblock %}""", title="Login")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/home")
def home():
    if not require_login():
        return redirect(url_for("login"))
    m = Merchant.query.filter_by(mid="DEMO_MID_001").first()
    return render_template_string(BASE + """
    {% block content %}
    <h3>Card Terminal</h3>
    <form method='post' action='{{ url_for("punch") }}'>
      Amount: <input name='amount' required><br>
      MID: <input name='mid' value='DEMO_MID_001' required><br>
      TID: <input name='tid' value='TERM001' required><br>
      Currency: <select name='currency'><option>USD</option><option>EUR</option></select><br>
      Protocol: <select name='protocol'>
        {% for name, need in protocols.items() %}
          <option value='{{ name }}'>{{ name }} ({{ need }} digits)</option>
        {% endfor %}
      </select><br>
      Issuer Auth Code (F38): <input name='auth_code'><br>
      <button>Process</button>
    </form>
    {% endblock %}""", title="Home", protocols=PROTOCOLS, m=m)

@app.route("/punch", methods=["POST"])
def punch():
    if not require_login():
        return redirect(url_for("login"))
    amount_cents = dollars_to_cents(request.form.get("amount","0"))
    mid = request.form.get("mid")
    tid = request.form.get("tid")
    currency = request.form.get("currency","USD")
    protocol = request.form.get("protocol")
    auth_code = (request.form.get("auth_code") or "").strip()

    rrn = uuid4().hex[:12].upper()
    stan = uuid4().hex[:6].upper()

    if not auth_code:
        need = PROTOCOLS.get(protocol, 6)
        auth_code = uuid4().hex[:need].upper()

    if not validate_auth_code(protocol, auth_code):
        flash(f"Auth code must be {PROTOCOLS.get(protocol)} digits")
        return redirect(url_for("home"))

    resp_code = "00" if amount_cents > 0 else "12"
    m = Merchant.query.filter_by(mid=mid).first()
    if not m:
        m = Merchant(mid=mid, payout_method=DEFAULT_PAYOUT_METHOD, chain=DEFAULT_CHAIN, address="WalletXYZ")
        db.session.add(m); db.session.commit()

    tx = Transaction(
        mti="0210", protocol=protocol, rrn=rrn, stan=stan, tid=tid, mid=mid,
        amount_cents=amount_cents, currency=currency, resp_code=resp_code,
        auth_code=auth_code, status=("approved" if resp_code=="00" else "declined"),
        payout_method=m.payout_method, payout_chain=m.chain, payout_address=m.address
    )
    db.session.add(tx); db.session.commit()

    if resp_code != "00":
        flash("Declined by issuer")
        return redirect(url_for("monitor"))

    max_gas_allowed = compute_gas_caps(amount_cents)
    est_fee = simulate_network_fee_usd(tx.payout_chain, amount_cents) if m.payout_method=="CRYPTO" else Decimal("0.00")

    return render_template_string(BASE + """
    {% block content %}
    <h3>Approved (MTI 0210)</h3>
    <p>Protocol: {{ tx.protocol }}</p>
    <p>Auth Code: {{ tx.auth_code }}</p>
    <p>Amount: {{ cents_to_display(tx.amount_cents) }} {{ tx.currency }}</p>
    {% if tx.payout_method=="CRYPTO" %}
      <p>Wallet: {{ tx.payout_chain }} {{ tx.payout_address }}</p>
      <p>Max gas: ${{ max_gas_allowed }} | Est fee: ${{ est_fee }}</p>
    {% else %}
      <p>Bank payout will be used</p>
    {% endif %}
    <form method='post' action='{{ url_for("send_payout", tx_id=tx.id) }}'>
      <button {% if tx.payout_method=="CRYPTO" and est_fee > max_gas_allowed %}disabled{% endif %}>Trigger Payout</button>
    </form>
    {% endblock %}""", title="Approved", tx=tx, cents_to_display=cents_to_display,
        max_gas_allowed=max_gas_allowed, est_fee=est_fee)

@app.route("/payout/<int:tx_id>", methods=["POST"])
def send_payout(tx_id):
    if not require_login():
        return redirect(url_for("login"))
    tx = Transaction.query.get_or_404(tx_id)

    if tx.payout_method == "CRYPTO":
        allowed = compute_gas_caps(tx.amount_cents)
        est_fee = simulate_network_fee_usd(tx.payout_chain, tx.amount_cents)
        if est_fee > allowed:
            tx.status = "payout_failed"
            tx.notes = "Gas too high"
            db.session.commit()
            flash("Gas too high")
            return redirect(url_for("monitor"))
        txh, fee = simulate_send_crypto(tx.payout_chain, tx.payout_address, tx.amount_cents)
        tx.tx_hash = txh
        tx.notes = f"Crypto fee ${fee}"
        tx.status = "payout_sent"
    else:
        bank_ref, fee = simulate_bank_transfer(tx.mid, tx.amount_cents, tx.currency)
        tx.payout_bank_ref = bank_ref
        tx.notes = f"Bank fee ${fee}"
        tx.status = "payout_sent"

    db.session.commit()
    flash("Payout sent")
    return redirect(url_for("monitor"))

@app.route("/merchants", methods=["GET","POST"])
def merchants():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        mid = request.form.get("mid") or "DEMO_MID_001"
        payout_method = request.form.get("payout_method") or DEFAULT_PAYOUT_METHOD
        m = Merchant.query.filter_by(mid=mid).first()
        if not m: m = Merchant(mid=mid)
        m.payout_method = payout_method
        if payout_method == "CRYPTO":
            m.chain = request.form.get("chain") or DEFAULT_CHAIN
            m.address = request.form.get("address")
        else:
            m.bank_name = request.form.get("bank_name")
            m.account_name = request.form.get("account_name")
            m.account_no = request.form.get("account_no")
            m.ifsc_swift = request.form.get("ifsc_swift")
        db.session.add(m); db.session.commit()
        flash("Merchant updated")
        return redirect(url_for("merchants"))
    items = Merchant.query.all()
    return render_template_string(BASE + """
    {% block content %}
    <h3>Merchants</h3>
    <form method='post'>
      MID: <input name='mid'><br>
      Method: <select name='payout_method'><option>CRYPTO</option><option>BANK</option></select><br>
      Chain: <input name='chain'><br>
      Address: <input name='address'><br>
      Bank: <input name='bank_name'><br>
      Acc Name: <input name='account_name'><br>
      Acc No: <input name='account_no'><br>
      IFSC/SWIFT: <input name='ifsc_swift'><br>
      <button>Save</button>
    </form>
    {% endblock %}""", title="Merchants", items=items)

@app.route("/monitor")
def monitor():
    if not require_login():
        return redirect(url_for("login"))
    txs = Transaction.query.order_by(Transaction.created_at.desc()).all()
    return render_template_string(BASE + """
    {% block content %}
    <h3>Transaction History</h3>
    <table border=1>
      <tr><th>When</th><th>Protocol</th><th>Amount</th><th>Status</th><th>Auth</th></tr>
      {% for t in txs %}
      <tr>
        <td>{{ t.created_at }}</td><td>{{ t.protocol }}</td><td>{{ cents_to_display(t.amount_cents) }}</td><td>{{ t.status }}</td><td>{{ t.auth_code }}</td>
      </tr>
      {% endfor %}
    </table>
    {% endblock %}""", title="History", cents_to_display=cents_to_display, txs=txs)

@app.before_first_request
def init_db():
    db.create_all()
    if not Merchant.query.filter_by(mid="DEMO_MID_001").first():
        db.session.add(Merchant(mid="DEMO_MID_001", payout_method=DEFAULT_PAYOUT_METHOD, chain=DEFAULT_CHAIN, address="WalletXYZ"))
        db.session.commit()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
