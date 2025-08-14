import os
from datetime import datetime
from uuid import uuid4
from decimal import Decimal, ROUND_HALF_UP

from flask import (
    Flask, request, session, redirect, url_for,
    render_template, render_template_string, flash
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# 2FA
import pyotp

# ------------------ Config ------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///app.db")
# Seed admin (used only on first run to create the account)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_SEED = os.getenv("ADMIN_PASSWORD", "admin123")
ADMIN_TOTP_SEED = os.getenv("TOTP_SECRET")  # if absent, one will be generated

MAX_GAS_USD = Decimal(os.getenv("MAX_GAS_USD", "5"))
MAX_GAS_PCT = Decimal(os.getenv("MAX_GAS_PCT", "1.5"))
DEFAULT_CHAIN = os.getenv("DEFAULT_CHAIN", "TRC20")
DEFAULT_PAYOUT_METHOD = os.getenv("DEFAULT_PAYOUT_METHOD", "BANK")  # CRYPTO or BANK

# Protocols & required auth-code length (F38)
PROTOCOLS = {
    "POS Terminal -101.1 (4-digit approval)": 4,
    "POS Terminal -101.4 (6-digit approval)": 6,
    "POS Terminal -101.6 (Pre-authorization)": 6,
    "POS Terminal -101.7 (4-digit approval)": 4,
    "POS Terminal -101.8 (PIN-LESS transaction)": 4,
    "POS Terminal -201.1 (6-digit approval)": 6,
    "POS Terminal -201.3 (6-digit approval)": 6,
    "POS Terminal -201.5 (6-digit approval)": 6,
}

# ------------------ App / DB ------------------
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------ Models ------------------
class Merchant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    mid = db.Column(db.String(64), unique=True, index=True)
    payout_method = db.Column(db.String(16), default=DEFAULT_PAYOUT_METHOD)
    chain = db.Column(db.String(16), default=DEFAULT_CHAIN)
    address = db.Column(db.String(128))
    bank_name = db.Column(db.String(64))
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

class AdminUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, index=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    totp_secret = db.Column(db.String(64), nullable=False)  # base32

# ------------------ Helpers ------------------
def require_login():
    return bool(session.get("user"))

def dollars_to_cents(amount_str):
    try:
        amt = Decimal(amount_str).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
        return int(amt * 100)
    except Exception:
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

def mask_pan(pan):
    digits = "".join(ch for ch in pan if ch.isdigit())
    if len(digits) < 8:
        return "*" * (len(digits) - 4) + digits[-4:]
    return digits[:6] + "*" * (len(digits) - 10) + digits[-4:]

def get_admin():
    return AdminUser.query.filter_by(username=ADMIN_USERNAME).first()

# ------------------ Auth / Session ------------------
@app.route("/", methods=["GET"])
def root():
    return redirect(url_for("dashboard") if session.get("user") else url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    # Renders templates/login.html you provided (expects username & password fields)
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = (request.form.get("password") or "")
        admin = AdminUser.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session["user"] = admin.username
            flash("Logged in.")
            return redirect(url_for("dashboard"))
        flash("Invalid credentials.")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

# -------- Forgot Password (via TOTP) ----------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    # Single-page flow: username + TOTP + new password
    error = success = None
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        otp = (request.form.get("otp") or "").strip()
        new = request.form.get("new") or ""
        confirm = request.form.get("confirm") or ""

        admin = AdminUser.query.filter_by(username=username).first()
        if not admin:
            error = "User not found."
        elif not (new and new == confirm):
            error = "New password and confirmation must match."
        else:
            totp = pyotp.TOTP(admin.totp_secret)
            if not totp.verify(otp, valid_window=1):
                error = "Invalid or expired TOTP."
            else:
                admin.password_hash = generate_password_hash(new)
                db.session.commit()
                success = "Password reset successful. You can now log in."
                flash(success)
                return redirect(url_for("login"))

    # Inline minimal template so you don't need another file
    return render_template_string(
        """
        {% extends "base.html" %}
        {% block content %}
        <h2>Reset Password (TOTP)</h2>
        {% if error %}<p style="color:red">{{ error }}</p>{% endif %}
        {% if success %}<p style="color:green">{{ success }}</p>{% endif %}
        <form method="POST" class="form-wrap">
          <label>User ID:</label><br>
          <input type="text" name="username" required><br>
          <label>Authenticator Code (TOTP):</label><br>
          <input type="text" name="otp" required><br>
          <label>New Password:</label><br>
          <input type="password" name="new" required><br>
          <label>Confirm New Password:</label><br>
          <input type="password" name="confirm" required><br>
          <button type="submit">Reset Password</button>
        </form>
        <p style="margin-top:10px">Use your Authy / Google Authenticator app for the code.</p>
        {% endblock %}
        """,
        error=error, success=success
    )

# Optional: show current user's TOTP setup (secret + provisioning URI)
@app.route("/totp-setup")
def totp_setup():
    if not require_login():
        return redirect(url_for("login"))
    admin = get_admin()
    if not admin:
        flash("Admin user not found.")
        return redirect(url_for("dashboard"))

    issuer = "RUTLAND_POS"
    account_name = admin.username
    uri = pyotp.totp.TOTP(admin.totp_secret).provisioning_uri(name=account_name, issuer_name=issuer)

    # Inline simple page (you can create a template later if you like)
    return render_template_string(
        """
        {% extends "base.html" %}
        {% block content %}
        <h2>TOTP Setup</h2>
        <p><strong>Secret:</strong> {{ secret }}</p>
        <p><strong>Issuer:</strong> {{ issuer }}</p>
        <p><strong>Account:</strong> {{ account }}</p>
        <p><strong>URI (copy into Authy/Google Authenticator):</strong></p>
        <code style="display:block;word-break:break-all">{{ uri }}</code>
        <p class="note">Security tip: after enrolling your device, keep the secret safe.</p>
        {% endblock %}
        """,
        secret=admin.totp_secret, issuer=issuer, account=account_name, uri=uri
    )

# ------------------ UI Pages ------------------
@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))
    return render_template("dashboard.html")

@app.route("/protocol", methods=["GET", "POST"])
def protocol():
    if not require_login():
        return redirect(url_for("login"))

    if request.method == "POST":
        selected_protocol = request.form.get("protocol")
        if selected_protocol not in PROTOCOLS:
            flash("Please select a valid protocol.")
            return redirect(url_for("protocol"))
        session["selected_protocol"] = selected_protocol
        return redirect(url_for("card"))

    return render_template("protocol.html", protocols=list(PROTOCOLS.keys()))

@app.route("/card", methods=["GET", "POST"])
def card():
    if not require_login():
        return redirect(url_for("login"))
    if "selected_protocol" not in session:
        flash("Select a protocol first.")
        return redirect(url_for("protocol"))

    if request.method == "POST":
        pan = (request.form.get("pan") or "").strip()
        expiry = (request.form.get("expiry") or "").strip()
        cvv = (request.form.get("cvv") or "").strip()

        digits_only = "".join(ch for ch in pan if ch.isdigit())
        if not (12 <= len(digits_only) <= 19):
            flash("Card number must be 12–19 digits.")
            return redirect(url_for("card"))

        if len(expiry) != 5 or expiry[2] != "/":
            flash("Expiry must be in MM/YY format.")
            return redirect(url_for("card"))
        mm = expiry[:2]
        yy = expiry[3:]
        if not (mm.isdigit() and yy.isdigit() and 1 <= int(mm) <= 12):
            flash("Invalid expiry date.")
            return redirect(url_for("card"))

        if not (cvv.isdigit() and len(cvv) == 4):
            flash("CVV/CVC must be 4 digits.")
            return redirect(url_for("card"))

        session["card_pan"] = digits_only
        session["card_masked"] = mask_pan(digits_only)
        session["card_expiry"] = expiry
        session["card_cvv"] = cvv
        return redirect(url_for("auth"))

    return render_template("card.html")

@app.route("/auth", methods=["GET", "POST"])
def auth():
    if not require_login():
        return redirect(url_for("login"))
    if "selected_protocol" not in session:
        flash("Select a protocol first.")
        return redirect(url_for("protocol"))

    warning = None
    need = PROTOCOLS.get(session["selected_protocol"], 6)

    if request.method == "POST":
        code = (request.form.get("auth") or "").strip()
        if not (code.isdigit() and len(code) == need):
            warning = f"Auth code must be {need} digits."
            return render_template("Auth.html", warning=warning)
        session["auth_code"] = code
        return redirect(url_for("amount"))

    return render_template("Auth.html", warning=warning)

@app.route("/amount", methods=["GET", "POST"])
def amount():
    if not require_login():
        return redirect(url_for("login"))
    if "selected_protocol" not in session or "auth_code" not in session:
        flash("Please complete protocol and auth first.")
        return redirect(url_for("protocol"))

    if request.method == "POST":
        amount_str = request.form.get("amount", "0")
        amount_cents = dollars_to_cents(amount_str)
        if amount_cents <= 0:
            flash("Enter a valid amount.")
            return redirect(url_for("amount"))

        # Demo fields
        mid = "DEMO_MID_001"
        tid = "TERM001"
        currency = "USD"

        # Ensure merchant exists
        m = Merchant.query.filter_by(mid=mid).first()
        if not m:
            m = Merchant(
                mid=mid,
                payout_method=DEFAULT_PAYOUT_METHOD,
                chain=DEFAULT_CHAIN,
                address="WalletXYZ"
            )
            db.session.add(m)
            db.session.commit()

        rrn = uuid4().hex[:12].upper()
        stan = uuid4().hex[:6].upper()
        protocol = session["selected_protocol"]
        auth_code = session["auth_code"]

        # Create TX
        tx = Transaction(
            mti="0210",
            protocol=protocol,
            rrn=rrn,
            stan=stan,
            tid=tid,
            mid=mid,
            amount_cents=amount_cents,
            currency=currency,
            resp_code="00",
            auth_code=auth_code,
            status="approved",
            payout_method=m.payout_method,
            payout_chain=m.chain,
            payout_address=m.address,
            notes=f"PAN {session.get('card_masked','')} EXP {session.get('card_expiry','')}"
        )
        db.session.add(tx)
        db.session.commit()

        # Optional: auto-payout
        if tx.payout_method == "CRYPTO":
            allowed = compute_gas_caps(tx.amount_cents)
            est_fee = simulate_network_fee_usd(tx.payout_chain, tx.amount_cents)
            if est_fee <= allowed:
                txh, fee = simulate_send_crypto(tx.payout_chain, tx.payout_address, tx.amount_cents)
                tx.tx_hash = txh
                tx.notes = (tx.notes or "") + f" | Crypto fee ${fee}"
                tx.status = "payout_sent"
                db.session.commit()
            else:
                tx.status = "payout_failed"
                tx.notes = (tx.notes or "") + " | Gas too high"
                db.session.commit()
                flash("Approved, but payout skipped (gas too high).")
        else:
            bank_ref, fee = simulate_bank_transfer(tx.mid, tx.amount_cents, tx.currency)
            tx.payout_bank_ref = bank_ref
            tx.notes = (tx.notes or "") + f" | Bank fee ${fee}"
            tx.status = "payout_sent"
            db.session.commit()

        flash("Approved (MTI 0210).")
        return redirect(url_for("monitor"))

    return render_template("amount.html")

# ------------------ Merchants ------------------
@app.route("/merchants", methods=["GET", "POST"])
def merchants():
    if not require_login():
        return redirect(url_for("login"))

    if request.method == "POST":
        mid = request.form.get("mid") or "DEMO_MID_001"
        payout_method = request.form.get("payout_method") or DEFAULT_PAYOUT_METHOD
        m = Merchant.query.filter_by(mid=mid).first()
        if not m:
            m = Merchant(mid=mid)
        m.payout_method = payout_method
        if payout_method == "CRYPTO":
            m.chain = request.form.get("chain") or DEFAULT_CHAIN
            m.address = request.form.get("address")
        else:
            m.bank_name = request.form.get("bank_name")
            m.account_name = request.form.get("account_name")
            m.account_no = request.form.get("account_no")
            m.ifsc_swift = request.form.get("ifsc_swift")
        db.session.add(m)
        db.session.commit()
        flash("Merchant updated.")
        return redirect(url_for("merchants"))

    items = Merchant.query.all()
    # Temporary inline list; you can move to a merchants.html later
    rows = "".join(
        f"<tr><td>{m.mid}</td><td>{m.payout_method}</td><td>{m.chain or ''}</td><td>{m.address or ''}</td></tr>"
        for m in items
    )
    html = f"""
    <h3>Merchants</h3>
    <form method='post' class='form-wrap'>
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
    <hr>
    <table border=1 cellpadding=6>
      <tr><th>MID</th><th>Method</th><th>Chain</th><th>Address</th></tr>
      {rows}
    </table>
    """
    return render_template_string("{% extends 'base.html' %}{% block content %}" + html + "{% endblock %}")

# ------------------ Monitor ------------------
@app.route("/monitor")
def monitor():
    if not require_login():
        return redirect(url_for("login"))
    txs = Transaction.query.order_by(Transaction.created_at.desc()).all()

    def row(t):
        return f"<tr><td>{t.created_at}</td><td>{t.protocol}</td><td>{cents_to_display(t.amount_cents)} {t.currency}</td>" \
               f"<td>{t.status}</td><td>{t.auth_code}</td><td>{t.notes or ''}</td></tr>"

    rows = "".join(row(t) for t in txs)
    html = f"""
    <h3>Transaction History</h3>
    <table border=1 cellpadding=6>
      <tr><th>When</th><th>Protocol</th><th>Amount</th><th>Status</th><th>Auth</th><th>Notes</th></tr>
      {rows}
    </table>
    """
    return render_template_string("{% extends 'base.html' %}{% block content %}" + html + "{% endblock %}")

# ------------------ Change Password ------------------
@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if not require_login():
        return redirect(url_for("login"))

    admin = get_admin()
    if not admin:
        flash("Admin user not found.")
        return redirect(url_for("dashboard"))

    error = success = None
    if request.method == "POST":
        curr = request.form.get("current") or ""
        new = request.form.get("new") or ""
        confirm = request.form.get("confirm") or ""

        if not check_password_hash(admin.password_hash, curr):
            error = "Current password is incorrect."
        elif not new or new != confirm:
            error = "New password and confirmation must match."
        else:
            admin.password_hash = generate_password_hash(new)
            db.session.commit()
            success = "Password updated."

    return render_template("password.html", error=error, success=success)

# ------------------ Init DB at Startup ------------------
with app.app_context():
    db.create_all()

    # Ensure demo merchant exists
    if not Merchant.query.filter_by(mid="DEMO_MID_001").first():
        db.session.add(Merchant(
            mid="DEMO_MID_001",
            payout_method=DEFAULT_PAYOUT_METHOD,
            chain=DEFAULT_CHAIN,
            address="WalletXYZ"
        ))
        db.session.commit()

    # Ensure admin user exists
    admin = AdminUser.query.filter_by(username=ADMIN_USERNAME).first()
    if not admin:
        seed_secret = ADMIN_TOTP_SEED or pyotp.random_base32()
        admin = AdminUser(
            username=ADMIN_USERNAME,
            password_hash=generate_password_hash(ADMIN_PASSWORD_SEED),
            totp_secret=seed_secret
        )
        db.session.add(admin)
        db.session.commit()
        print("=== Admin user created ===")
        print(f"Username: {ADMIN_USERNAME}")
        print(f"Seed password: {ADMIN_PASSWORD_SEED}")
        print(f"TOTP secret (save to Authy/Google Authenticator): {seed_secret}")
        print("You can also visit /totp-setup after login to view the provisioning URI.")

# ------------------ Run ------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
