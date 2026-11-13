"""
Team Netflix - Flask app on top of your SQLite database.

  * Customer site : login, "who's watching", browse, search, title pages,
                    watched / liked, profile editing with picture upload.
  * Admin dashboard (/admin): stats, add / edit / delete rows in every table
                    (the original auto-generated CRUD), poster + avatar uploads,
                    and the "who watched which films" analytics view.
                    Only accounts with is_admin = 1 can open it.

Setup:
    pip install flask
    python netflix_app.py
Then open http://127.0.0.1:5000

On first run the app adds three things to your database (back it up first):
    account.is_admin   - 0/1 flag for admin accounts
    film.poster        - poster filename / URL (blank = generated placeholder)
    tv_show.poster     - same, for TV shows
and, if no admin exists yet, creates admin@teamnetflix.com with a random
password that is printed once in the terminal.

Command line helpers:
    python netflix_app.py make-admin someone@example.com
    python netflix_app.py set-password someone@example.com
"""
import getpass
import hashlib
import os
import re
import secrets
import sqlite3
import sys
import textwrap
import uuid
from functools import wraps
from pathlib import Path
from xml.sax.saxutils import escape as xml_escape

from flask import (Flask, Response, abort, flash, g, redirect, render_template,
                   request, send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "team_netflix.db"
UPLOAD_DIR = BASE_DIR / "uploads"
MAX_UPLOAD_BYTES = 2 * 1024 * 1024
MAX_PROFILES_PER_ACCOUNT = 5
PAGE_SIZE = 50
KID_BLOCKED_GENRES = {"Horror", "Thriller", "Crime", "War"}

# kind -> (table, id column in link tables, cast table, director table)
KINDS = {
    "film": ("film", "film_id", "film_actors", "film_directors"),
    "tv": ("tv_show", "tv_show_id", "tv_actors", "tv_directors"),
}
# columns that hold an image: column name -> upload sub-folder
FILE_COLS = {"poster": "posters", "profile_picture": "avatars"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 6 * 1024 * 1024


def _load_secret():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    f = BASE_DIR / ".secret_key"
    if not f.exists():
        f.write_text(secrets.token_hex(32))
    return f.read_text().strip()


app.secret_key = _load_secret()
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")


# ======================================================================
# database
# ======================================================================
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def next_id(db, table, col):
    return db.execute(f'SELECT COALESCE(MAX("{col}"), 0) + 1 FROM "{table}"').fetchone()[0]


def init_db():
    """Add the columns this app needs (safe to run every start-up)."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row

    def cols(t):
        return [r["name"] for r in db.execute(f'PRAGMA table_info("{t}")')]

    if "is_admin" not in cols("account"):
        db.execute("ALTER TABLE account ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
    for t in ("film", "tv_show"):
        if "poster" not in cols(t):
            db.execute(f'ALTER TABLE "{t}" ADD COLUMN poster VARCHAR(255)')
    try:
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_account_email ON account(email)")
    except sqlite3.Error:
        print("Note: duplicate emails exist, so emails were not made unique.")

    if not db.execute("SELECT 1 FROM account WHERE is_admin = 1").fetchone():
        email = "admin@teamnetflix.com"
        pw = secrets.token_urlsafe(9)
        existing = db.execute("SELECT id FROM account WHERE email = ?", (email,)).fetchone()
        if existing:
            db.execute("UPDATE account SET is_admin = 1, password = ? WHERE id = ?",
                       (generate_password_hash(pw), existing["id"]))
        else:
            aid = next_id(db, "account", "id")
            db.execute(
                "INSERT INTO account (id, email, password, subscription_id, account_created, is_admin) "
                "VALUES (?, ?, ?, 1, datetime('now'), 1)",
                (aid, email, generate_password_hash(pw)))
            db.execute(
                "INSERT INTO profile (account_id, profile_id, profile_name, profile_picture, is_kid_profile) "
                "VALUES (?, ?, 'Admin', 'avatar_red.png', 0)",
                (aid, next_id(db, "profile", "profile_id")))
        print("=" * 60)
        print(" No admin account existed, so one was created:")
        print(f"   email:    {email}")
        print(f"   password: {pw}")
        print(" Sign in, then change the password under Account.")
        print("=" * 60)
    db.commit()
    db.close()


# ======================================================================
# auth helpers
# ======================================================================
def verify_password(stored, supplied):
    if not stored:
        return False
    if stored.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored, supplied)
    # legacy plain-text value from the seed data
    return secrets.compare_digest(stored.encode(), supplied.encode())


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


@app.before_request
def load_user_and_check_csrf():
    g.account = None
    g.profile = None
    if request.method == "POST":
        sent = request.form.get("csrf", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Your session expired. Go back, refresh the page and try again.")
    aid = session.get("account_id")
    if aid:
        g.account = get_db().execute("SELECT * FROM account WHERE id = ?", (aid,)).fetchone()
        if g.account is None:
            session.clear()
        else:
            pid = session.get("profile_id")
            if pid:
                g.profile = get_db().execute(
                    "SELECT * FROM profile WHERE profile_id = ? AND account_id = ?",
                    (pid, aid)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.account is None:
            return redirect(url_for("login", next=request.full_path.rstrip("?")))
        return view(*a, **kw)
    return wrapped


def profile_required(view):
    @wraps(view)
    @login_required
    def wrapped(*a, **kw):
        if g.profile is None:
            return redirect(url_for("profiles"))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*a, **kw):
        if not g.account["is_admin"]:
            abort(403, "This area is for administrators only.")
        return view(*a, **kw)
    return wrapped


def safe_next(target):
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return None


# ======================================================================
# images: uploads, default avatars, generated posters
# ======================================================================
def sniff_image(b):
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if b.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if b[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "webp"
    return None


def save_image(file_storage, subdir):
    """Validate + store an uploaded image. Returns the new filename or None."""
    if not file_storage or not file_storage.filename:
        return None
    data = file_storage.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise ValueError("Image must be smaller than 2 MB.")
    ext = sniff_image(data)
    if not ext:
        raise ValueError("Please upload a PNG, JPG, GIF or WebP image.")
    folder = UPLOAD_DIR / subdir
    folder.mkdir(parents=True, exist_ok=True)
    name = f"u_{uuid.uuid4().hex}.{ext}"
    (folder / name).write_bytes(data)
    return name


_UPLOAD_NAME = re.compile(r"^u_[0-9a-f]{32}\.(png|jpg|gif|webp)$")


def remove_upload(subdir, name):
    if name and _UPLOAD_NAME.match(name):
        try:
            (UPLOAD_DIR / subdir / name).unlink()
        except OSError:
            pass


AVATAR_COLORS = {"red": "#e5383b", "blue": "#2b7de9", "green": "#2fa84f", "purple": "#8e44ad",
                 "orange": "#f08c00", "yellow": "#f5c518", "teal": "#14a3a3", "gray": "#7a7f87",
                 "cat": "#f4a261", "panda": "#eeeeee"}
DEFAULT_AVATARS = [f"avatar_{k}.png" for k in AVATAR_COLORS]


def avatar_svg(key):
    c = AVATAR_COLORS.get(key, "#7a7f87")
    ink = "#222"
    extra = ""
    eyes = f'<circle cx="38" cy="50" r="5" fill="{ink}"/><circle cx="62" cy="50" r="5" fill="{ink}"/>'
    if key == "cat":
        extra = (f'<polygon points="18,34 26,8 44,24" fill="{c}"/>'
                 f'<polygon points="82,34 74,8 56,24" fill="{c}"/>')
    elif key == "panda":
        extra = (f'<circle cx="22" cy="24" r="12" fill="#222"/><circle cx="78" cy="24" r="12" fill="#222"/>'
                 f'<ellipse cx="36" cy="50" rx="9" ry="11" fill="#222"/><ellipse cx="64" cy="50" rx="9" ry="11" fill="#222"/>')
        eyes = '<circle cx="36" cy="50" r="4" fill="#fff"/><circle cx="64" cy="50" r="4" fill="#fff"/>'
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
            f'<rect width="100" height="100" fill="{c}"/>'
            f'<g>{extra}</g>'
            f'<circle cx="50" cy="56" r="34" fill="{c}" stroke="rgba(0,0,0,.15)" stroke-width="2"/>'
            f'{eyes}<path d="M36 68 Q50 80 64 68" fill="none" stroke="{ink}" stroke-width="4" stroke-linecap="round"/>'
            f'</svg>')


GENRE_PALETTE = {
    "Sci-Fi": ("#0b1f3a", "#2a7fa8"), "Action": ("#3a0b0b", "#c0392b"),
    "Crime": ("#1c1c1c", "#6b5b3e"), "Romance": ("#4a1030", "#d6457a"),
    "Thriller": ("#10162b", "#4b3f8f"), "Comedy": ("#4a3a00", "#e1a800"),
    "Horror": ("#150000", "#7a0f0f"), "Drama": ("#1e2433", "#5c6f91"),
    "Animation": ("#0d3b3b", "#3fbf9f"), "Fantasy": ("#2a1048", "#8e5bd6"),
    "War": ("#1f2415", "#6e7c3d"), "Western": ("#3b2412", "#c27a3a"),
}
FALLBACK_PALETTE = [("#1e2433", "#5c6f91"), ("#2b1e33", "#8a5cab"), ("#173529", "#3f9b72")]


def poster_svg(title, genre, kind):
    pair = GENRE_PALETTE.get(genre)
    if not pair:
        pair = FALLBACK_PALETTE[int(hashlib.md5((title or "").encode()).hexdigest(), 16) % len(FALLBACK_PALETTE)]
    lines = textwrap.wrap(title or "Untitled", 13)[:5] or ["Untitled"]
    start = 205 - (len(lines) - 1) * 22
    text = "".join(
        f'<text x="150" y="{start + i * 44}" text-anchor="middle" font-size="34" font-weight="800" '
        f'fill="#fff" font-family="Helvetica,Arial,sans-serif">{xml_escape(t)}</text>'
        for i, t in enumerate(lines))
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 300 450">'
            f'<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="{pair[0]}"/><stop offset="1" stop-color="{pair[1]}"/></linearGradient></defs>'
            f'<rect width="300" height="450" fill="url(#g)"/>'
            f'<text x="150" y="48" text-anchor="middle" font-size="15" letter-spacing="4" fill="#fff" opacity=".7" '
            f'font-family="Helvetica,Arial,sans-serif">{"SERIES" if kind == "tv" else "FILM"}</text>'
            f'{text}'
            f'<text x="150" y="420" text-anchor="middle" font-size="16" fill="#fff" opacity=".75" '
            f'font-family="Helvetica,Arial,sans-serif">{xml_escape(genre or "")}</text></svg>')


def avatar_url(name):
    if name and name.startswith("u_"):
        return url_for("media", kind="avatars", filename=name)
    if name and name in DEFAULT_AVATARS:
        return url_for("default_avatar", name=name)
    return url_for("default_avatar", name="avatar_gray.png")


def poster_url(kind, tid, title, genre, poster):
    if poster and poster.startswith(("http://", "https://")):
        return poster
    if poster and poster.startswith("u_"):
        return url_for("media", kind="posters", filename=poster)
    return url_for("poster_placeholder", kind=kind, tid=tid)


def runtime_text(kind, minutes):
    if not minutes:
        return ""
    if kind == "tv":
        return f"{minutes}m / episode"
    h, m = divmod(int(minutes), 60)
    return f"{h}h {m:02d}m" if h else f"{m}m"


app.jinja_env.globals.update(csrf=csrf_token, avatar_url=avatar_url, poster_url=poster_url,
                             runtime_text=runtime_text, default_avatars=DEFAULT_AVATARS)


@app.route("/media/<kind>/<path:filename>")
def media(kind, filename):
    if kind not in FILE_COLS.values():
        abort(404)
    return send_from_directory(UPLOAD_DIR / kind, filename, max_age=3600)


@app.route("/avatar/<name>")
def default_avatar(name):
    if name not in DEFAULT_AVATARS:
        abort(404)
    key = name[len("avatar_"):-len(".png")]
    return Response(avatar_svg(key), mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.route("/poster/<kind>/<int:tid>.svg")
def poster_placeholder(kind, tid):
    if kind not in KINDS:
        abort(404)
    row = get_db().execute(f'SELECT title, genre FROM "{KINDS[kind][0]}" WHERE id = ?', (tid,)).fetchone()
    if row is None:
        abort(404)
    return Response(poster_svg(row["title"], row["genre"], kind), mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=3600"})


# ======================================================================
# customer site
# ======================================================================
@app.route("/")
def home():
    if g.account is None:
        return redirect(url_for("login"))
    return redirect(url_for("browse") if g.profile else url_for("profiles"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.account is not None:
        return redirect(url_for("home"))
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        acct = db.execute("SELECT * FROM account WHERE lower(email) = lower(?)", (email,)).fetchone()
        if acct and verify_password(acct["password"], password):
            if not acct["password"].startswith(("scrypt:", "pbkdf2:")):  # upgrade legacy plain text
                db.execute("UPDATE account SET password = ? WHERE id = ?",
                           (generate_password_hash(password), acct["id"]))
                db.commit()
            session.clear()
            session["account_id"] = acct["id"]
            nxt = safe_next(request.args.get("next"))
            if nxt:
                return redirect(nxt)
            return redirect(url_for("profiles"))
        flash("Incorrect email or password.")
    return render_template("login.html")


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if g.account is not None:
        return redirect(url_for("home"))
    db = get_db()
    plans = db.execute("SELECT * FROM subscription ORDER BY subscription_price, id").fetchall()
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()[:30] or None
        password = request.form.get("password", "")
        again = request.form.get("again", "")
        pname = request.form.get("profile_name", "").strip()
        plan = request.form.get("plan", "")
        error = None
        if not _EMAIL_RE.match(email) or len(email) > 255:
            error = "Please enter a valid email address."
        elif db.execute("SELECT 1 FROM account WHERE lower(email) = lower(?)", (email,)).fetchone():
            error = "An account with that email already exists. Try signing in."
        elif len(password) < 8:
            error = "Your password must be at least 8 characters."
        elif password != again:
            error = "The passwords don't match."
        elif not pname or len(pname) > 30:
            error = "Please enter a profile name (up to 30 characters)."
        elif not any(str(p["id"]) == plan for p in plans):
            error = "Please choose a plan."
        if error:
            flash(error)
        else:
            try:
                aid = next_id(db, "account", "id")
                db.execute(
                    "INSERT INTO account (id, email, password, phone_number, subscription_id, account_created, is_admin) "
                    "VALUES (?, ?, ?, ?, ?, datetime('now'), 0)",
                    (aid, email, generate_password_hash(password), phone, int(plan)))
                pid = next_id(db, "profile", "profile_id")
                db.execute(
                    "INSERT INTO profile (account_id, profile_id, profile_name, profile_picture, is_kid_profile) "
                    "VALUES (?, ?, ?, 'avatar_gray.png', 0)", (aid, pid, pname))
                db.commit()
            except sqlite3.Error:
                db.rollback()
                flash("Could not create your account. Please try again.")
            else:
                session.clear()
                session["account_id"] = aid
                session["profile_id"] = pid
                flash("Welcome to Team Netflix! You can change your picture under Manage profiles.", "ok")
                return redirect(url_for("browse"))
    return render_template("signup.html", plans=plans)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/profiles")
@login_required
def profiles():
    rows = get_db().execute("SELECT * FROM profile WHERE account_id = ? ORDER BY profile_id",
                            (g.account["id"],)).fetchall()
    return render_template("profiles.html", profiles=rows, manage=bool(request.args.get("manage")),
                           can_add=len(rows) < MAX_PROFILES_PER_ACCOUNT)


@app.route("/profiles/<int:pid>/select")
@login_required
def select_profile(pid):
    row = get_db().execute("SELECT 1 FROM profile WHERE profile_id = ? AND account_id = ?",
                           (pid, g.account["id"])).fetchone()
    if not row:
        abort(404)
    session["profile_id"] = pid
    return redirect(url_for("browse"))


def _get_own_profile(pid):
    row = get_db().execute("SELECT * FROM profile WHERE profile_id = ? AND account_id = ?",
                           (pid, g.account["id"])).fetchone()
    if not row:
        abort(404)
    return row


def _profile_form(existing):
    """Shared by 'new' and 'edit'. Returns (values, error)."""
    name = request.form.get("profile_name", "").strip()
    kid = 1 if request.form.get("is_kid_profile") else 0
    if not name:
        return None, "Please enter a profile name."
    if len(name) > 30:
        return None, "Profile names can be at most 30 characters."
    picture = existing["profile_picture"] if existing else "avatar_gray.png"
    chosen = request.form.get("avatar", "")
    if chosen in DEFAULT_AVATARS:
        picture = chosen
    new_file = None
    try:
        new_file = save_image(request.files.get("picture"), "avatars")
    except ValueError as e:
        return None, str(e)
    if new_file:
        picture = new_file
    return {"name": name, "kid": kid, "picture": picture}, None


@app.route("/profiles/new", methods=["GET", "POST"])
@login_required
def new_profile():
    db = get_db()
    count = db.execute("SELECT COUNT(*) FROM profile WHERE account_id = ?", (g.account["id"],)).fetchone()[0]
    if count >= MAX_PROFILES_PER_ACCOUNT:
        flash(f"You can have at most {MAX_PROFILES_PER_ACCOUNT} profiles.")
        return redirect(url_for("profiles"))
    if request.method == "POST":
        vals, err = _profile_form(None)
        if err:
            flash(err)
        else:
            db.execute("INSERT INTO profile (account_id, profile_id, profile_name, profile_picture, is_kid_profile) "
                       "VALUES (?, ?, ?, ?, ?)",
                       (g.account["id"], next_id(db, "profile", "profile_id"),
                        vals["name"], vals["picture"], vals["kid"]))
            db.commit()
            flash("Profile created.", "ok")
            return redirect(url_for("profiles"))
    return render_template("profile_form.html", profile=None)


@app.route("/profiles/<int:pid>/edit", methods=["GET", "POST"])
@login_required
def edit_profile(pid):
    db = get_db()
    prof = _get_own_profile(pid)
    if request.method == "POST":
        vals, err = _profile_form(prof)
        if err:
            flash(err)
        else:
            if vals["picture"] != prof["profile_picture"]:
                remove_upload("avatars", prof["profile_picture"])
            db.execute("UPDATE profile SET profile_name = ?, profile_picture = ?, is_kid_profile = ? "
                       "WHERE profile_id = ?", (vals["name"], vals["picture"], vals["kid"], pid))
            db.commit()
            flash("Profile saved.", "ok")
            return redirect(url_for("profiles"))
    return render_template("profile_form.html", profile=prof)


@app.route("/profiles/<int:pid>/delete", methods=["POST"])
@login_required
def delete_profile(pid):
    db = get_db()
    prof = _get_own_profile(pid)
    count = db.execute("SELECT COUNT(*) FROM profile WHERE account_id = ?", (g.account["id"],)).fetchone()[0]
    if count <= 1:
        flash("You need at least one profile.")
        return redirect(url_for("edit_profile", pid=pid))
    db.execute("DELETE FROM profile WHERE profile_id = ?", (pid,))
    db.commit()
    remove_upload("avatars", prof["profile_picture"])
    if session.get("profile_id") == pid:
        session.pop("profile_id", None)
    flash("Profile deleted.", "ok")
    return redirect(url_for("profiles"))


def title_cards(db, rows_sql_where="", params=(), kind_filter=None):
    """Fetch title dicts (films + shows) for the current profile."""
    kid = bool(g.profile and g.profile["is_kid_profile"])
    out = []
    for kind, (table, col, actors, directors) in KINDS.items():
        if kind_filter and kind != kind_filter:
            continue
        sql = (f'SELECT t.id, t.title, t.duration, t.genre, t.poster, '
               f'(SELECT COUNT(*) FROM watched w WHERE w.{col} = t.id AND w.is_watched = 1) AS watches, '
               f'(SELECT COUNT(*) FROM liked l WHERE l.{col} = t.id AND l.is_liked = 1) AS likes '
               f'FROM "{table}" t {rows_sql_where} ORDER BY t.title')
        for r in db.execute(sql, params):
            if kid and r["genre"] in KID_BLOCKED_GENRES:
                continue
            out.append({"kind": kind, "id": r["id"], "title": r["title"], "genre": r["genre"],
                        "duration": r["duration"], "watches": r["watches"], "likes": r["likes"],
                        "poster": poster_url(kind, r["id"], r["title"], r["genre"], r["poster"])})
    return out


@app.route("/browse")
@profile_required
def browse():
    db = get_db()
    titles = title_cards(db)
    rows = []
    trending = sorted(titles, key=lambda t: (t["watches"] + t["likes"], t["title"]), reverse=True)[:15]
    rows.append(("Trending now", trending))
    films = [t for t in titles if t["kind"] == "film"]
    shows = [t for t in titles if t["kind"] == "tv"]
    for label, group in (("Movies", films), ("TV Shows", shows)):
        by_genre = {}
        for t in group:
            by_genre.setdefault(t["genre"] or "Other", []).append(t)
        for genre, items in sorted(by_genre.items(), key=lambda kv: -len(kv[1])):
            if len(items) >= 3:
                rows.append((f"{label}: {genre}", items))
    hero = trending[0] if trending else None
    return render_template("browse.html", rows=rows, hero=hero)


@app.route("/search")
@profile_required
def search():
    q = request.args.get("q", "").strip()
    results = []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        db = get_db()
        for kind, (table, col, actors, directors) in KINDS.items():
            where = (f"WHERE t.title LIKE ? ESCAPE '\\' "
                     f"OR t.id IN (SELECT x.{col} FROM {actors} x JOIN actor a ON a.id = x.actor_id "
                     f"WHERE a.first_name || ' ' || a.last_name LIKE ? ESCAPE '\\') "
                     f"OR t.id IN (SELECT x.{col} FROM {directors} x JOIN director d ON d.id = x.director_id "
                     f"WHERE d.first_name || ' ' || d.last_name LIKE ? ESCAPE '\\')")
            results += title_cards(db, where, (like, like, like), kind_filter=kind)
    return render_template("grid.html", heading=f'Results for "{q}"' if q else "Search",
                           titles=results, empty="No matches. Try a title, actor or director.", q=q)


def _link_state(db, kind, tid):
    col = KINDS[kind][1]
    w = db.execute(f"SELECT 1 FROM watched WHERE account_id = ? AND {col} = ? AND is_watched = 1",
                   (g.account["id"], tid)).fetchone()
    l = db.execute(f"SELECT is_liked FROM liked WHERE account_id = ? AND {col} = ?",
                   (g.account["id"], tid)).fetchone()
    return bool(w), (None if l is None else bool(l["is_liked"]))


@app.route("/title/<kind>/<int:tid>")
@profile_required
def title(kind, tid):
    if kind not in KINDS:
        abort(404)
    table, col, actors, directors = KINDS[kind]
    db = get_db()
    row = db.execute(f'SELECT * FROM "{table}" WHERE id = ?', (tid,)).fetchone()
    if row is None:
        abort(404)
    if g.profile["is_kid_profile"] and row["genre"] in KID_BLOCKED_GENRES:
        abort(404)
    cast = db.execute(f"SELECT DISTINCT a.first_name || ' ' || a.last_name AS name FROM actor a "
                      f"JOIN {actors} x ON x.actor_id = a.id WHERE x.{col} = ? ORDER BY name", (tid,)).fetchall()
    dirs = db.execute(f"SELECT DISTINCT d.first_name || ' ' || d.last_name AS name FROM director d "
                      f"JOIN {directors} x ON x.director_id = d.id WHERE x.{col} = ? ORDER BY name", (tid,)).fetchall()
    watched, liked = _link_state(db, kind, tid)
    similar = [t for t in title_cards(db, "WHERE t.genre = ? AND t.id != ?", (row["genre"], tid), kind_filter=kind)][:8]
    return render_template("title.html", kind=kind, t=row, cast=[c["name"] for c in cast],
                           directors=[d["name"] for d in dirs], watched=watched, liked=liked, similar=similar,
                           poster=poster_url(kind, tid, row["title"], row["genre"], row["poster"]))


@app.route("/title/<kind>/<int:tid>/watched", methods=["POST"])
@profile_required
def toggle_watched(kind, tid):
    if kind not in KINDS:
        abort(404)
    table, col, _, _ = KINDS[kind]
    db = get_db()
    if not db.execute(f'SELECT 1 FROM "{table}" WHERE id = ?', (tid,)).fetchone():
        abort(404)
    watched, _ = _link_state(db, kind, tid)
    db.execute(f"DELETE FROM watched WHERE account_id = ? AND {col} = ?", (g.account["id"], tid))
    if not watched:
        other = "tv_show_id" if col == "film_id" else "film_id"
        db.execute(f"INSERT INTO watched (account_id, is_watched, {col}, {other}) VALUES (?, 1, ?, NULL)",
                   (g.account["id"], tid))
    db.commit()
    return redirect(url_for("title", kind=kind, tid=tid))


@app.route("/title/<kind>/<int:tid>/like", methods=["POST"])
@profile_required
def set_like(kind, tid):
    if kind not in KINDS:
        abort(404)
    table, col, _, _ = KINDS[kind]
    action = request.form.get("action")
    if action not in ("like", "dislike", "clear"):
        abort(400)
    db = get_db()
    if not db.execute(f'SELECT 1 FROM "{table}" WHERE id = ?', (tid,)).fetchone():
        abort(404)
    db.execute(f"DELETE FROM liked WHERE account_id = ? AND {col} = ?", (g.account["id"], tid))
    if action != "clear":
        other = "tv_show_id" if col == "film_id" else "film_id"
        db.execute(f"INSERT INTO liked (account_id, is_liked, {col}, {other}) VALUES (?, ?, ?, NULL)",
                   (g.account["id"], 1 if action == "like" else 0, tid))
    db.commit()
    return redirect(url_for("title", kind=kind, tid=tid))


@app.route("/my-list")
@profile_required
def my_list():
    db = get_db()
    aid = g.account["id"]
    watched, liked = [], []
    for t in title_cards(db):
        col = KINDS[t["kind"]][1]
        if db.execute(f"SELECT 1 FROM watched WHERE account_id=? AND {col}=? AND is_watched=1", (aid, t["id"])).fetchone():
            watched.append(t)
        if db.execute(f"SELECT 1 FROM liked WHERE account_id=? AND {col}=? AND is_liked=1", (aid, t["id"])).fetchone():
            liked.append(t)
    return render_template("my_list.html", watched=watched, liked=liked)


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    db = get_db()
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        again = request.form.get("again", "")
        if not verify_password(g.account["password"], current):
            flash("Your current password is incorrect.")
        elif len(new) < 8:
            flash("The new password must be at least 8 characters.")
        elif new != again:
            flash("The new passwords don't match.")
        else:
            db.execute("UPDATE account SET password = ? WHERE id = ?", (generate_password_hash(new), g.account["id"]))
            db.commit()
            flash("Password updated.", "ok")
        return redirect(url_for("account"))
    sub = db.execute("SELECT * FROM subscription WHERE id = ?", (g.account["subscription_id"],)).fetchone()
    return render_template("account.html", sub=sub)


# ======================================================================
# admin dashboard
# ======================================================================
def get_tables(db):
    rows = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
    return [r["name"] for r in rows]


def label_expr(db, table):
    cols = db.execute(f'PRAGMA table_info("{table}")').fetchall()
    names = [c["name"] for c in cols]
    if "first_name" in names and "last_name" in names:
        return "first_name || ' ' || last_name"
    for c in cols:
        if not c["pk"] and any(t in (c["type"] or "").upper() for t in ("CHAR", "TEXT")):
            return f'"{c["name"]}"'
    return None


def fk_options(db, table, to_col):
    if to_col is None:
        pk = [c["name"] for c in db.execute(f'PRAGMA table_info("{table}")') if c["pk"]]
        to_col = pk[0] if pk else None
    if to_col is None:
        return None
    label = label_expr(db, table)
    try:
        if label:
            sql = f'SELECT "{to_col}" AS v, {label} AS l FROM "{table}" ORDER BY l'
        else:
            sql = f'SELECT "{to_col}" AS v, "{to_col}" AS l FROM "{table}" ORDER BY v'
        return [(r["v"], f'{r["l"]} (#{r["v"]})') for r in db.execute(sql)]
    except sqlite3.Error:
        return None


def describe(db, table):
    cols = db.execute(f'PRAGMA table_info("{table}")').fetchall()
    fks = {r["from"]: r for r in db.execute(f'PRAGMA foreign_key_list("{table}")')}
    pk_cols = [c for c in cols if c["pk"]]
    auto_pk = pk_cols[0]["name"] if len(pk_cols) == 1 and "INT" in (pk_cols[0]["type"] or "").upper() else None
    fields = []
    for c in cols:
        name, typ = c["name"], (c["type"] or "").upper()
        f = {"name": name, "label": name.replace("_", " ").title(),
             "required": bool(c["notnull"]) and name != auto_pk and c["dflt_value"] is None,
             "hint": "Leave blank to auto-assign" if name == auto_pk else "",
             "input": "text", "options": None, "file": name in FILE_COLS}
        opts = fk_options(db, fks[name]["table"], fks[name]["to"]) if name in fks else None
        if opts is not None:
            f["options"] = opts
        elif "BOOL" in typ or name.startswith("is_"):
            f["options"] = [(1, "Yes"), (0, "No")]
        elif name == "password":
            f["input"] = "password"
        elif "email" in name.lower():
            f["input"] = "email"
        elif "DATETIME" in typ or "TIMESTAMP" in typ:
            f["input"] = "datetime-local"
        elif "DATE" in typ:
            f["input"] = "date"
        elif any(t in typ for t in ("DEC", "REAL", "FLOA", "DOUB", "NUM")):
            f["input"], f["step"] = "number", "any"
        elif "INT" in typ:
            f["input"] = "number"
        if f["file"]:
            f["hint"] = "URL or filename (or upload a file)"
        fields.append(f)
    return {"table": table, "auto_pk": auto_pk, "fields": fields}


def _collect_values(fields, existing=None):
    """Read the admin form. Returns (values dict, error or None)."""
    values = {}
    for f in fields:
        name = f["name"]
        raw = request.form.get(name, "").strip()
        if f["file"]:
            try:
                up = save_image(request.files.get(name + "__file"), FILE_COLS[name])
            except ValueError as e:
                return None, str(e)
            if up:
                raw = up
        if name == "password":
            if not raw:
                continue  # blank on edit = keep; blank on add = NULL
            raw = generate_password_hash(raw)
        if f["input"] == "datetime-local":
            raw = raw.replace("T", " ")
        if existing is not None:
            values[name] = raw if raw != "" else None
        elif raw != "":
            values[name] = raw
    return values, None


def _friendly_error(e):
    msg = str(e)
    if "FOREIGN KEY" in msg:
        return ("Other rows still depend on this one (or the value you chose doesn't exist). "
                "Remove or fix the related rows first.")
    if "UNIQUE" in msg:
        return "That value is already in use (for example, the email belongs to another account)."
    return msg


@app.route("/admin")
@admin_required
def admin_home():
    db = get_db()
    q = lambda sql: db.execute(sql).fetchone()[0]
    stats = [("Accounts", q("SELECT COUNT(*) FROM account")), ("Profiles", q("SELECT COUNT(*) FROM profile")),
             ("Films", q("SELECT COUNT(*) FROM film")), ("TV shows", q("SELECT COUNT(*) FROM tv_show")),
             ("Watched", q("SELECT COUNT(*) FROM watched WHERE is_watched = 1")),
             ("Liked", q("SELECT COUNT(*) FROM liked WHERE is_liked = 1"))]
    plans = db.execute(
        "SELECT s.subscription_type AS plan, s.subscription_price AS price, s.subscription_duration AS months, "
        "COUNT(a.id) AS accounts FROM subscription s LEFT JOIN account a ON a.subscription_id = s.id "
        "GROUP BY s.id ORDER BY s.id").fetchall()
    monthly = sum((p["price"] or 0) / (p["months"] or 1) * p["accounts"] for p in plans)
    top = db.execute(
        "SELECT title, kind, SUM(c) AS n FROM ("
        " SELECT f.title AS title, 'Film' AS kind, COUNT(*) AS c FROM watched w JOIN film f ON f.id = w.film_id WHERE w.is_watched = 1 GROUP BY f.id"
        " UNION ALL"
        " SELECT s.title, 'TV', COUNT(*) FROM watched w JOIN tv_show s ON s.id = w.tv_show_id WHERE w.is_watched = 1 GROUP BY s.id"
        ") GROUP BY title, kind ORDER BY n DESC, title LIMIT 8").fetchall()
    recent = db.execute("SELECT id, email, account_created FROM account ORDER BY account_created DESC LIMIT 8").fetchall()
    return render_template("admin/dashboard.html", tables=get_tables(db), active="home", stats=stats,
                           plans=plans, monthly=monthly, top=top, recent=recent)


@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    db = get_db()
    try:
        rows = db.execute("SELECT account_id, email, film_title FROM netflix_watched_user_results "
                          "ORDER BY film_title, email").fetchall()
    except sqlite3.Error as e:
        flash(f"Could not load analytics: {e}")
        rows = []
    return render_template("admin/analytics.html", tables=get_tables(db), active="analytics", rows=rows)


def _admin_table(db, table):
    if table not in get_tables(db):
        abort(404)
    return describe(db, table)


@app.route("/admin/t/<table>", methods=["GET", "POST"])
@admin_required
def admin_table(table):
    db = get_db()
    info = _admin_table(db, table)
    fields = info["fields"]

    if request.method == "POST":
        values, err = _collect_values(fields)
        if err:
            flash(err)
            return redirect(url_for("admin_table", table=table))
        pk = info["auto_pk"]
        if pk and pk not in values:
            values[pk] = next_id(db, table, pk)
        if not values:
            flash("Nothing to add.")
            return redirect(url_for("admin_table", table=table))
        cols = list(values)
        sql = (f'INSERT INTO "{table}" ({", ".join(chr(34) + c + chr(34) for c in cols)}) '
               f'VALUES ({", ".join("?" for _ in cols)})')
        try:
            db.execute(sql, [values[c] for c in cols])
            db.commit()
            flash("Row added.", "ok")
        except sqlite3.Error as e:
            db.rollback()
            flash(f"Could not add row: {_friendly_error(e)}")
        return redirect(url_for("admin_table", table=table))

    lookups = {f["name"]: {str(v): t for v, t in f["options"]} for f in fields if f["options"] is not None}
    names = [f["name"] for f in fields]
    kind = {"film": "film", "tv_show": "tv"}.get(table)
    page = max(int(request.args.get("p", 1) or 1), 1) if str(request.args.get("p", "1")).isdigit() else 1
    total = db.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0]
    rows = []
    for r in db.execute(f'SELECT rowid AS _rowid_, * FROM "{table}" ORDER BY rowid LIMIT ? OFFSET ?',
                        (PAGE_SIZE, (page - 1) * PAGE_SIZE)):
        cells = []
        for f in fields:
            val = r[f["name"]]
            if f["name"] == "poster" and kind:
                cells.append({"img": poster_url(kind, r["id"], r["title"], r["genre"], val), "wide": True})
            elif f["name"] == "profile_picture":
                cells.append({"img": avatar_url(val), "wide": False})
            elif val is None:
                cells.append("")
            elif f["name"] == "password":
                cells.append("••••••••")
            elif f["name"] in lookups:
                cells.append(lookups[f["name"]].get(str(val), val))
            else:
                cells.append(val)
        rows.append({"rowid": r["_rowid_"], "cells": cells})
    return render_template("admin/table.html", tables=get_tables(db), active=table, page_name=table,
                           fields=fields, rows=rows, total=total, page=page,
                           pages=max((total + PAGE_SIZE - 1) // PAGE_SIZE, 1))


@app.route("/admin/t/<table>/edit/<int:rowid>", methods=["GET", "POST"])
@admin_required
def admin_edit(table, rowid):
    db = get_db()
    info = _admin_table(db, table)
    fields = info["fields"]
    row = db.execute(f'SELECT rowid AS _rowid_, * FROM "{table}" WHERE rowid = ?', (rowid,)).fetchone()
    if row is None:
        abort(404)
    own = table == "account" and row["id"] == g.account["id"]
    if request.method == "POST":
        values, err = _collect_values(fields, existing=row)
        if err:
            flash(err)
            return redirect(url_for("admin_edit", table=table, rowid=rowid))
        missing = [f["label"] for f in fields if f["required"] and f["name"] in values and values[f["name"]] is None]
        if missing:
            flash("Required: " + ", ".join(missing))
            return redirect(url_for("admin_edit", table=table, rowid=rowid))
        if own and str(values.get("is_admin", 1)) != "1":
            flash("You can't remove your own admin access.")
            return redirect(url_for("admin_edit", table=table, rowid=rowid))
        if not values:
            return redirect(url_for("admin_table", table=table))
        sets = ", ".join(f'"{c}" = ?' for c in values)
        try:
            db.execute(f'UPDATE "{table}" SET {sets} WHERE rowid = ?', [*values.values(), rowid])
            db.commit()
            for col, sub in FILE_COLS.items():  # clean up replaced uploads
                if col in values and values[col] != row[col]:
                    remove_upload(sub, row[col])
            flash("Row saved.", "ok")
        except sqlite3.Error as e:
            db.rollback()
            flash(f"Could not save row: {_friendly_error(e)}")
            return redirect(url_for("admin_edit", table=table, rowid=rowid))
        return redirect(url_for("admin_table", table=table))

    current = {}
    for f in fields:
        v = row[f["name"]]
        if f["name"] == "password":
            v = ""
        elif v is not None and f["input"] == "datetime-local":
            v = str(v).replace(" ", "T")[:16]
        current[f["name"]] = "" if v is None else v
    return render_template("admin/edit.html", tables=get_tables(db), active=table, page_name=table,
                           fields=fields, current=current, rowid=rowid)


@app.route("/admin/t/<table>/delete/<int:rowid>", methods=["POST"])
@admin_required
def admin_delete(table, rowid):
    db = get_db()
    _admin_table(db, table)
    row = db.execute(f'SELECT rowid AS _rowid_, * FROM "{table}" WHERE rowid = ?', (rowid,)).fetchone()
    if row is None:
        abort(404)
    if table == "account" and row["id"] == g.account["id"]:
        flash("You can't delete the account you are signed in with.")
        return redirect(url_for("admin_table", table=table))
    try:
        db.execute(f'DELETE FROM "{table}" WHERE rowid = ?', (rowid,))
        db.commit()
        for col, sub in FILE_COLS.items():
            if col in row.keys():
                remove_upload(sub, row[col])
        flash("Row deleted.", "ok")
    except sqlite3.Error as e:
        db.rollback()
        flash(f"Could not delete row: {_friendly_error(e)}")
    return redirect(url_for("admin_table", table=table))


# ======================================================================
# errors + CLI
# ======================================================================
@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def show_error(e):
    msg = {413: "That file is too large (limit 2 MB per image)."}.get(e.code, e.description)
    return render_template("error.html", code=e.code, message=msg), e.code


def cli(argv):
    cmd, email = argv[0], argv[1] if len(argv) > 1 else None
    if cmd not in ("make-admin", "set-password") or not email:
        raise SystemExit(__doc__.split("Command line helpers:")[1].strip())
    db = sqlite3.connect(DB_PATH)
    acct = db.execute("SELECT id FROM account WHERE lower(email) = lower(?)", (email,)).fetchone()
    if not acct:
        raise SystemExit(f"No account with email {email}")
    if cmd == "make-admin":
        db.execute("UPDATE account SET is_admin = 1 WHERE id = ?", (acct[0],))
        print(f"{email} is now an admin.")
    else:
        pw = getpass.getpass("New password: ")
        if len(pw) < 8:
            raise SystemExit("Use at least 8 characters.")
        db.execute("UPDATE account SET password = ? WHERE id = ?", (generate_password_hash(pw), acct[0]))
        print("Password updated.")
    db.commit()


if __name__ == "__main__":
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}\nEdit DB_PATH at the top of the script.")
    init_db()
    if len(sys.argv) > 1:
        cli(sys.argv[1:])
    else:
        app.run(debug=True)
