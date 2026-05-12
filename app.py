import os
import sqlite3
import uuid
import random
from datetime import datetime
from flask import Flask, g, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "notebook.db")

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change_this_secret_key")
app.config["DATABASE"] = DB_PATH


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"], detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            verified INTEGER DEFAULT 0,
            otp_code TEXT,
            otp_created_at TIMESTAMP,
            active_session TEXT
        );

        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )
    db.commit()


def query_db(query, args=(), one=False):
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def generate_otp():
    return f"{random.randint(100000, 999999)}"


def create_session(user_id):
    session_token = str(uuid.uuid4())
    db = get_db()
    db.execute("UPDATE users SET active_session = ? WHERE id = ?", (session_token, user_id))
    db.commit()
    session["user_id"] = user_id
    session["session_token"] = session_token


def current_user():
    user_id = session.get("user_id")
    session_token = session.get("session_token")
    if not user_id or not session_token:
        return None
    user = query_db("SELECT * FROM users WHERE id = ?", (user_id,), one=True)
    if user is None or user["active_session"] != session_token:
        session.clear()
        return None
    return user


@app.before_request
def require_valid_session():
    if request.endpoint in ("dashboard", "new_note", "save_note", "logout", "profile"):
        if current_user() is None:
            return redirect(url_for("login"))


@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        if not phone or not password:
            flash("Phone number and password are required.", "warning")
            return redirect(url_for("signup"))

        if query_db("SELECT id FROM users WHERE phone = ?", (phone,), one=True):
            flash("A user with that phone number already exists.", "danger")
            return redirect(url_for("signup"))

        password_hash = generate_password_hash(password)
        otp_code = generate_otp()
        now = datetime.utcnow()
        db = get_db()
        db.execute(
            "INSERT INTO users (phone, password_hash, verified, otp_code, otp_created_at) VALUES (?, ?, 0, ?, ?)",
            (phone, password_hash, otp_code, now),
        )
        db.commit()
        flash("Signup successful. Enter the OTP to verify your phone number.", "success")
        return render_template("verify.html", phone=phone, otp_code=otp_code)
    return render_template("signup.html")


@app.route("/verify", methods=["POST"])
def verify():
    phone = request.form.get("phone", "").strip()
    otp_input = request.form.get("otp", "").strip()
    user = query_db("SELECT * FROM users WHERE phone = ?", (phone,), one=True)
    if not user:
        flash("Phone number not found.", "danger")
        return redirect(url_for("signup"))

    if user["otp_code"] != otp_input:
        flash("OTP is incorrect.", "danger")
        return render_template("verify.html", phone=phone, otp_code=user["otp_code"])

    db = get_db()
    db.execute(
        "UPDATE users SET verified = 1, otp_code = NULL, otp_created_at = NULL WHERE id = ?",
        (user["id"],),
    )
    db.commit()
    flash("Phone verified successfully. You can now log in.", "success")
    return redirect(url_for("login"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        user = query_db("SELECT * FROM users WHERE phone = ?", (phone,), one=True)
        if not user:
            flash("Phone number not found.", "danger")
            return redirect(url_for("forgot_password"))
        otp_code = generate_otp()
        now = datetime.utcnow()
        db = get_db()
        db.execute(
            "UPDATE users SET otp_code = ?, otp_created_at = ? WHERE id = ?",
            (otp_code, now, user["id"]),
        )
        db.commit()
        flash("OTP generated. Enter it to reset your password.", "info")
        return render_template("forgot_verify.html", phone=phone, otp_code=otp_code)
    return render_template("forgot_password.html")


@app.route("/forgot-password/confirm", methods=["POST"])
def forgot_password_confirm():
    phone = request.form.get("phone", "").strip()
    otp_input = request.form.get("otp", "").strip()
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")
    user = query_db("SELECT * FROM users WHERE phone = ?", (phone,), one=True)
    if not user:
        flash("Phone number not found.", "danger")
        return redirect(url_for("forgot_password"))
    if user["otp_code"] != otp_input:
        flash("OTP is incorrect.", "danger")
        return render_template("forgot_verify.html", phone=phone, otp_code=user["otp_code"])
    if not new_password or new_password != confirm_password:
        flash("Passwords must match and cannot be empty.", "warning")
        return render_template("forgot_verify.html", phone=phone, otp_code=user["otp_code"])

    password_hash = generate_password_hash(new_password)
    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ?, otp_code = NULL, otp_created_at = NULL, active_session = NULL WHERE id = ?",
        (password_hash, user["id"]),
    )
    db.commit()
    flash("Password updated successfully. Please log in.", "success")
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        user = query_db("SELECT * FROM users WHERE phone = ?", (phone,), one=True)
        if not user:
            flash("Invalid phone number or password.", "danger")
            return redirect(url_for("login"))
        if not user["verified"]:
            flash("Please verify your phone number first.", "warning")
            return render_template("verify.html", phone=phone, otp_code=user["otp_code"])
        if not check_password_hash(user["password_hash"], password):
            flash("Invalid phone number or password.", "danger")
            return redirect(url_for("login"))

        create_session(user["id"])
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    user = current_user()
    if user:
        db = get_db()
        db.execute("UPDATE users SET active_session = NULL WHERE id = ?", (user["id"],))
        db.commit()
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
def profile():
    user = current_user()
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if not check_password_hash(user["password_hash"], current_password):
            flash("Current password is incorrect.", "danger")
            return render_template("profile.html", user=user)
        if not new_password or new_password != confirm_password:
            flash("New passwords must match and cannot be empty.", "warning")
            return render_template("profile.html", user=user)
        password_hash = generate_password_hash(new_password)
        db = get_db()
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user["id"]))
        db.commit()
        flash("Password changed successfully.", "success")
        return redirect(url_for("profile"))
    return render_template("profile.html", user=user)


@app.route("/dashboard")
def dashboard():
    user = current_user()
    search_title = request.args.get("title", "").strip()
    search_date = request.args.get("date", "").strip()
    query = "SELECT * FROM notes WHERE user_id = ?"
    params = [user["id"]]

    if search_title:
        query += " AND title LIKE ?"
        params.append(f"%{search_title}%")
    if search_date:
        query += " AND date(created_at) = ?"
        params.append(search_date)

    query += " ORDER BY created_at DESC"
    notes = query_db(query, tuple(params))
    return render_template("dashboard.html", user=user, notes=notes, search_title=search_title, search_date=search_date)


@app.route("/note/new")
def new_note():
    user = current_user()
    return render_template("note_editor.html", user=user, note=None)


@app.route("/note/save", methods=["POST"])
def save_note():
    user = current_user()
    title = request.form.get("title", "").strip()
    content = request.form.get("content", "").strip()
    if not title or not content:
        flash("Title and content are required.", "warning")
        return render_template("note_editor.html", user=user, note={"title": title, "content": content})

    now = datetime.utcnow()
    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (user["id"], title, content, now, now),
    )
    db.commit()
    flash("Note saved successfully.", "success")
    return redirect(url_for("dashboard"))


@app.route("/note/<int:note_id>")
def view_note(note_id):
    user = current_user()
    note = query_db("SELECT * FROM notes WHERE id = ? AND user_id = ?", (note_id, user["id"]), one=True)
    if not note:
        flash("Note not found.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("note_detail.html", note=note, user=user)


with app.app_context():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
