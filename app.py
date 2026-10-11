from flask import Flask, request, session, redirect, url_for, jsonify, send_from_directory, render_template_string, abort
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
from functools import wraps
from pathlib import Path
from secrets import token_urlsafe, compare_digest
from time import time
import sqlite3
import os
import uuid

# =========================
# ARVA MUSIC SERVER
# =========================

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
AUDIO_DIR = UPLOAD_DIR / "audio"
COVER_DIR = UPLOAD_DIR / "covers"
DB_FILE = BASE_DIR / "arva_music.db"

AUDIO_DIR.mkdir(parents=True, exist_ok=True)
COVER_DIR.mkdir(parents=True, exist_ok=True)

app = Flask(__name__)

SECRET_FILE = BASE_DIR / ".arva_secret_key"

if SECRET_FILE.exists():
    SECRET_KEY = SECRET_FILE.read_text().strip()
else:
    SECRET_KEY = token_urlsafe(64)
    SECRET_FILE.write_text(SECRET_KEY)

app.secret_key = os.environ.get("ARVA_SECRET_KEY") or SECRET_KEY

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    MAX_CONTENT_LENGTH=50 * 1024 * 1024,
    PERMANENT_SESSION_LIFETIME=1800
)

ADMIN_PASSWORD_HASH = os.environ.get("ARVA_ADMIN_PASSWORD_HASH")

ALLOWED_AUDIO = {"mp3", "wav", "ogg", "m4a", "aac", "flac"}
ALLOWED_IMAGES = {"jpg", "jpeg", "png", "webp"}

login_attempts = {}
MAX_ATTEMPTS = 5
LOCK_TIME = 15 * 60


# =========================
# DATABASE
# =========================

def db():
    connection = sqlite3.connect(DB_FILE)
    connection.row_factory = sqlite3.Row
    return connection


def init_db():
    connection = db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS songs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            artist TEXT NOT NULL,
            audio_file TEXT NOT NULL,
            cover_file TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


init_db()


# =========================
# SECURITY
# =========================

def client_ip():
    return request.remote_addr or "unknown"


def is_locked(ip):
    data = login_attempts.get(ip)

    if not data:
        return False

    if data["until"] <= time():
        login_attempts.pop(ip, None)
        return False

    return data["attempts"] >= MAX_ATTEMPTS


def failed_login(ip):
    data = login_attempts.setdefault(
        ip,
        {"attempts": 0, "until": 0}
    )

    data["attempts"] += 1

    if data["attempts"] >= MAX_ATTEMPTS:
        data["until"] = time() + LOCK_TIME


def successful_login(ip):
    login_attempts.pop(ip, None)


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = token_urlsafe(32)

    return session["csrf"]


def check_csrf():
    supplied = request.form.get("csrf", "")
    stored = session.get("csrf", "")

    if not stored or not compare_digest(supplied, stored):
        abort(403)


def admin_required(function):

    @wraps(function)
    def wrapper(*args, **kwargs):

        if not session.get("admin_authenticated"):
            return redirect(url_for("login"))

        session.permanent = True

        return function(*args, **kwargs)

    return wrapper


def allowed_file(filename, allowed):
    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()

    return extension in allowed


# =========================
# PUBLIC WEBSITE
# =========================

@app.route("/")
def home():
    index_path = BASE_DIR / "index.html"

    html = index_path.read_text(encoding="utf-8")

    is_authenticated = "true" if session.get("user_id") else "false"

    html = html.replace(
        "<head>",
        f"<head>\n<script>window.isAuthenticated = {is_authenticated};</script>",
        1
    )

    return html



@app.route("/api/songs/<int:song_id>/view", methods=["POST"])
def add_view(song_id):
    connection = db()

    song = connection.execute(
        "SELECT id FROM songs WHERE id = ?",
        (song_id,)
    ).fetchone()

    if not song:
        connection.close()
        return jsonify({"error": "آهنگ پیدا نشد"}), 404

    connection.execute(
        "UPDATE songs SET views = views + 1 WHERE id = ?",
        (song_id,)
    )

    connection.commit()
    connection.close()

    return jsonify({"success": True})


@app.route("/api/songs/<int:song_id>/like", methods=["POST"])
def add_like(song_id):

    user_id = session.get("user_id")

    if not user_id:
        return jsonify({
            "error": "برای لایک کردن باید وارد حساب شوید."
        }), 401

    connection = db()

    song = connection.execute(
        "SELECT id FROM songs WHERE id = ?",
        (song_id,)
    ).fetchone()

    if not song:
        connection.close()
        return jsonify({"error": "آهنگ پیدا نشد"}), 404

    existing_like = connection.execute(
        """
        SELECT 1 FROM song_likes
        WHERE user_id = ? AND song_id = ?
        """,
        (user_id, song_id)
    ).fetchone()

    if existing_like:

        connection.execute(
            """
            DELETE FROM song_likes
            WHERE user_id = ? AND song_id = ?
            """,
            (user_id, song_id)
        )

        liked = False

    else:

        connection.execute(
            """
            INSERT INTO song_likes (user_id, song_id)
            VALUES (?, ?)
            """,
            (user_id, song_id)
        )

        liked = True

    likes = connection.execute(
        """
        SELECT COUNT(*) AS total
        FROM song_likes
        WHERE song_id = ?
        """,
        (song_id,)
    ).fetchone()["total"]

    connection.execute(
        "UPDATE songs SET likes = ? WHERE id = ?",
        (likes, song_id)
    )

    connection.commit()
    connection.close()

    return jsonify({
        "success": True,
        "liked": liked,
        "likes": likes
    })


@app.route("/api/songs/<int:song_id>/download", methods=["POST"])
def add_download(song_id):
    connection = db()

    song = connection.execute(
        "SELECT id FROM songs WHERE id = ?",
        (song_id,)
    ).fetchone()

    if not song:
        connection.close()
        return jsonify({"error": "آهنگ پیدا نشد"}), 404

    connection.execute(
        "UPDATE songs SET downloads = downloads + 1 WHERE id = ?",
        (song_id,)
    )

    connection.commit()

    downloads = connection.execute(
        "SELECT downloads FROM songs WHERE id = ?",
        (song_id,)
    ).fetchone()["downloads"]

    connection.close()

    return jsonify({
        "success": True,
        "downloads": downloads
    })

@app.route("/api/songs")
def songs_api():

    connection = db()
    user_id = session.get("user_id")

    songs = connection.execute("""
        SELECT id, title, artist, audio_file, cover_file,
               views, likes, downloads
        FROM songs
        ORDER BY id DESC
    """).fetchall()

    result = []


    for song in songs:

        liked = False
        if user_id:
            liked = connection.execute(
                "SELECT 1 FROM song_likes WHERE user_id = ? AND song_id = ?",
                (user_id, song["id"])
            ).fetchone() is not None

        result.append({
            "id": song["id"],
            "liked": liked,
            "title": song["title"],
            "artist": song["artist"],
            "audio": url_for(
                "uploaded_file",
                kind="audio",
                filename=song["audio_file"]
            ),
            "cover": (
                url_for(
                    "uploaded_file",
                    kind="cover",
                    filename=song["cover_file"]
                )
                if song["cover_file"] else None
            ),
            "views": song["views"],
            "likes": song["likes"],
            "downloads": song["downloads"]
        })

    connection.close()
    return jsonify(result)


@app.route("/uploads/<kind>/<filename>")
def uploaded_file(kind, filename):

    if kind == "audio" and not session.get("user_id"):
        return jsonify({
            "error": "برای پخش آهنگ باید وارد حساب شوید."
        }), 401

    if kind == "audio":
        directory = AUDIO_DIR

    elif kind == "cover":
        directory = COVER_DIR

    else:
        abort(404)

    return send_from_directory(directory, filename)


# =========================
# LOGIN
# =========================

LOGIN_PAGE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARVA MUSIC — Admin</title>

<style>
*{box-sizing:border-box}

body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}

.box{
    width:min(420px,90%);
    padding:35px;
    background:#101014;
    border:1px solid #29292e;
    border-radius:22px;
}

.logo{
    text-align:center;
    font-size:28px;
    font-weight:900;
    letter-spacing:3px;
}

.logo span{color:#ff176d}

.sub{
    text-align:center;
    color:#777;
    margin:10px 0 30px;
    font-size:13px;
}

input{
    width:100%;
    padding:14px;
    border-radius:11px;
    border:1px solid #29292e;
    background:#08080a;
    color:white;
    outline:none;
    margin-bottom:12px;
}

button{
    width:100%;
    border:0;
    border-radius:11px;
    padding:14px;
    color:white;
    font-weight:bold;
    background:linear-gradient(135deg,#ff176d,#ff1744);
}
</style>
</head>

<body>

<div class="box">

<div class="logo">
ARVA <span>MUSIC</span>
</div>

<div class="sub">پنل مدیریت خصوصی</div>

{% if error %}
<div style="color:#ff668f;margin-bottom:15px">
{{ error }}
</div>
{% endif %}

<form method="POST">

<div style="position:relative">
<input
type="password"
name="password"
id="admin-password"
placeholder="رمز عبور"
autocomplete="current-password"
required
style="padding-left:55px"
>

<button
type="button"
id="toggle-password"
aria-label="نمایش رمز"
style="
position:absolute;
left:8px;
top:50%;
transform:translateY(-50%);
width:42px;
height:42px;
padding:0;
background:transparent;
border:0;
color:#aaa;
font-size:20px;
cursor:pointer;
">
👁️
</button>
</div>

<script>
const passwordInput = document.getElementById("admin-password");
const togglePassword = document.getElementById("toggle-password");

togglePassword.addEventListener("click", function () {
    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        togglePassword.textContent = "🙈";
        togglePassword.setAttribute("aria-label", "مخفی کردن رمز");
    } else {
        passwordInput.type = "password";
        togglePassword.textContent = "👁️";
        togglePassword.setAttribute("aria-label", "نمایش رمز");
    }
});
</script>

<input type="hidden" name="csrf" value="{{ csrf }}">

<button type="submit">
ورود به پنل
</button>

</form>

</div>




</body>
</html>
"""


@app.route("/admin/login", methods=["GET", "POST"])
def login():

    if session.get("admin_authenticated"):
        return redirect(url_for("admin"))

    ip = client_ip()

    if is_locked(ip):

        return render_template_string(
            LOGIN_PAGE,
            error="تلاش‌های ورود بیش از حد مجاز است.",
            csrf=csrf_token()
        )

    if request.method == "POST":

        check_csrf()

        password = request.form.get("password", "")

        if not ADMIN_PASSWORD_HASH:

            return render_template_string(
                LOGIN_PAGE,
                error="رمز ادمین تنظیم نشده است.",
                csrf=csrf_token()
            )

        if check_password_hash(
            ADMIN_PASSWORD_HASH,
            password
        ):

            successful_login(ip)

            session.clear()

            session["admin_authenticated"] = True
            session["csrf"] = token_urlsafe(32)
            session.permanent = True

            return redirect(url_for("admin"))

        failed_login(ip)

        return render_template_string(
            LOGIN_PAGE,
            error="رمز عبور اشتباه است.",
            csrf=csrf_token()
        )

    return render_template_string(
        LOGIN_PAGE,
        error=None,
        csrf=csrf_token()
    )


# =========================
# ADMIN PANEL
# =========================

ADMIN_PAGE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>ARVA MUSIC — مدیریت</title>

<style>

*{box-sizing:border-box}

body{
    margin:0;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}

header{
    height:70px;
    padding:0 7%;
    display:flex;
    align-items:center;
    justify-content:space-between;
    border-bottom:1px solid #222;
    background:#090909;
}

.logo{
    font-size:23px;
    font-weight:900;
    letter-spacing:2px;
}

.logo span{color:#ff176d}

.logout{
    color:#ff6c94;
    text-decoration:none;
}

main{
    width:min(900px,92%);
    margin:45px auto;
}

h1{
    font-size:32px;
}

.sub{
    color:#777;
    margin-bottom:30px;
}

.panel{
    background:#101014;
    border:1px solid #24242a;
    border-radius:20px;
    padding:25px;
    margin-bottom:30px;
}

input{
    width:100%;
    padding:14px;
    margin-bottom:13px;
    background:#08080a;
    color:white;
    border:1px solid #29292e;
    border-radius:10px;
}

label{
    display:block;
    padding:14px;
    margin-bottom:13px;
    border:1px dashed #393940;
    border-radius:10px;
    color:#aaa;
}

input[type=file]{
    display:none;
}

button{
    width:100%;
    padding:14px;
    border:0;
    border-radius:10px;
    color:white;
    font-weight:bold;
    background:linear-gradient(135deg,#ff176d,#ff1744);
}

.song{
    display:flex;
    align-items:center;
    gap:15px;
    padding:12px;
    margin-top:10px;
    background:#0a0a0c;
    border:1px solid #222;
    border-radius:12px;
}

.song-info{
    flex:1;
}

.artist{
    color:#777;
    font-size:12px;
    margin-top:4px;
}

.delete{
    width:auto;
    padding:9px 15px;
    background:#30101b;
    color:#ff6c94;
}

</style>

</head>

<body>

<header>

<div class="logo">
ARVA <span>MUSIC</span>
</div>

<div style="display:flex;align-items:center;gap:20px;">

<a href="/admin/friends" style="color:#ff176d;text-decoration:none;font-weight:bold;">
رفقا
</a>

<a class="logout" href="/admin/logout">
خروج
</a>

</div>

</header>

<main>

<h1>پنل مدیریت ARVA</h1>

<div class="sub">
فقط شما به این بخش دسترسی دارید.
</div>

<div class="panel">

<h3>🎵 انتشار آهنگ جدید</h3>

<form method="POST"
action="/admin/upload"
enctype="multipart/form-data">

<input
type="text"
name="title"
placeholder="نام آهنگ"
maxlength="120"
required
>

<input
type="text"
name="artist"
placeholder="نام خواننده"
maxlength="120"
required
>

<label>
🎧 انتخاب فایل آهنگ
<input
type="file"
name="audio"
accept=".mp3,.wav,.ogg,.m4a,.aac,.flac"
required
>
</label>

<label>
🖼️ انتخاب کاور
<input
type="file"
name="cover"
accept=".jpg,.jpeg,.png,.webp"
>
</label>

<input
type="hidden"
name="csrf"
value="{{ csrf }}"
>

<button type="submit">
انتشار آهنگ
</button>

</form>

</div>

<div class="panel">

<h3>🎶 آهنگ‌های منتشرشده</h3>

{% for song in songs %}

<div class="song">

<div class="song-info">

<strong>
{{ song["title"] }}
</strong>

<div class="artist">
{{ song["artist"] }}
</div>

</div>

<form
method="POST"
action="/admin/delete/{{ song['id'] }}"
>

<input
type="hidden"
name="csrf"
value="{{ csrf }}"
>

<button class="delete">
حذف
</button>

</form>

</div>

{% else %}

<div style="color:#666">
هنوز آهنگی منتشر نشده.
</div>

{% endfor %}

</div>

</main>



<script id="arva-cancel-buttons">
document.addEventListener("DOMContentLoaded", function () {
    const audioInput = document.querySelector('input[name="audio"]');
    const coverInput = document.querySelector('input[name="cover"]');

    function addCancelButton(input, label) {
        if (!input || input.parentElement.querySelector(".arva-cancel-file")) return;

        const button = document.createElement("button");
        button.type = "button";
        button.className = "arva-cancel-file";
        button.textContent = "✕ لغو انتخاب " + label;

        button.style.marginTop = "10px";
        button.style.padding = "10px 14px";
        button.style.border = "1px solid #444";
        button.style.borderRadius = "10px";
        button.style.background = "#181818";
        button.style.color = "#fff";
        button.style.cursor = "pointer";
        button.style.display = "none";

        input.parentElement.appendChild(button);

        input.addEventListener("change", function () {
            button.style.display = this.files.length ? "inline-block" : "none";
        });

        button.addEventListener("click", function () {
            input.value = "";
            input.dispatchEvent(new Event("change", { bubbles: true }));
            button.style.display = "none";
        });
    }

    addCancelButton(audioInput, "آهنگ");
    addCancelButton(coverInput, "کاور");
});
</script>

<script id="arva-preview-script">
document.addEventListener("DOMContentLoaded", function () {
    const audioInput = document.querySelector('input[name="audio"]');
    const coverInput = document.querySelector('input[name="cover"]');

    if (!audioInput || !coverInput) return;

    const audioBox = document.createElement("div");
    audioBox.style.marginTop = "12px";
    audioBox.style.padding = "14px";
    audioBox.style.border = "1px solid #333";
    audioBox.style.borderRadius = "14px";
    audioBox.style.background = "#111";

    const audioName = document.createElement("div");
    audioName.style.marginBottom = "10px";
    audioName.style.color = "#fff";

    const audioPlayer = document.createElement("audio");
    audioPlayer.controls = true;
    audioPlayer.style.width = "100%";
    audioPlayer.style.display = "none";

    audioBox.appendChild(audioName);
    audioBox.appendChild(audioPlayer);

    audioInput.parentElement.appendChild(audioBox);

    const coverBox = document.createElement("div");
    coverBox.style.marginTop = "12px";

    const coverPreview = document.createElement("img");
    coverPreview.style.width = "180px";
    coverPreview.style.height = "180px";
    coverPreview.style.objectFit = "cover";
    coverPreview.style.borderRadius = "18px";
    coverPreview.style.display = "none";
    coverPreview.style.border = "1px solid #333";

    coverBox.appendChild(coverPreview);
    coverInput.parentElement.appendChild(coverBox);

    audioInput.addEventListener("change", function () {
        const file = this.files[0];

        if (!file) {
            audioName.textContent = "";
            audioPlayer.style.display = "none";
            audioPlayer.removeAttribute("src");
            return;
        }

        audioName.textContent = "🎵 فایل انتخاب‌شده: " + file.name;

        const url = URL.createObjectURL(file);
        audioPlayer.src = url;
        audioPlayer.style.display = "block";
    });

    coverInput.addEventListener("change", function () {
        const file = this.files[0];

        if (!file) {
            coverPreview.style.display = "none";
            coverPreview.removeAttribute("src");
            return;
        }

        const url = URL.createObjectURL(file);
        coverPreview.src = url;
        coverPreview.style.display = "block";
    });
});
</script>


<script id="arva-upload-validation">
document.addEventListener("DOMContentLoaded", function () {
    const form = document.querySelector('form[action="/admin/upload"]');
    if (!form) return;

    const titleInput = form.querySelector('input[name="title"]');
    const artistInput = form.querySelector('input[name="artist"]');
    const audioInput = form.querySelector('input[name="audio"]');
    const coverInput = form.querySelector('input[name="cover"]');
    const submitButton = form.querySelector('button[type="submit"]');

    if (!titleInput || !artistInput || !audioInput || !coverInput || !submitButton) return;

    function updateUploadButton() {
        const ready =
            titleInput.value.trim() !== "" &&
            artistInput.value.trim() !== "" &&
            audioInput.files.length > 0 &&
            coverInput.files.length > 0;

        submitButton.disabled = !ready;
        submitButton.style.opacity = ready ? "1" : "0.45";
        submitButton.style.cursor = ready ? "pointer" : "not-allowed";
    }

    [titleInput, artistInput, audioInput, coverInput].forEach(function (input) {
        input.addEventListener("input", updateUploadButton);
        input.addEventListener("change", updateUploadButton);
    });

    updateUploadButton();
});
</script>

</body>
</html>
"""


# USER AUTHENTICATION
# =========================

REGISTER_PAGE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARVA MUSIC — ساخت حساب</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}
.auth-card{
    width:min(400px,100%);
    background:linear-gradient(145deg,#151515,#080808);
    border:1px solid rgba(255,0,90,.45);
    border-radius:22px;
    padding:32px 24px;
    box-shadow:0 20px 80px rgba(0,0,0,.7),0 0 40px rgba(255,0,90,.15);
}
.logo{
    text-align:center;
    color:#ff005a;
    font-size:32px;
    font-weight:900;
    letter-spacing:4px;
    margin-bottom:10px;
}
h1{
    text-align:center;
    font-size:22px;
    margin:0 0 24px;
}
label{
    display:block;
    margin:14px 0 7px;
    color:#ccc;
    font-size:14px;
}
input{
    width:100%;
    padding:13px 14px;
    border-radius:12px;
    border:1px solid #333;
    background:#0d0d0d;
    color:white;
    outline:none;
}
input:focus{
    border-color:#ff005a;
    box-shadow:0 0 12px rgba(255,0,90,.15);
}
button{
    width:100%;
    margin-top:22px;
    padding:14px;
    border:0;
    border-radius:12px;
    background:#ff005a;
    color:white;
    font-weight:800;
    cursor:pointer;
}
.error{
    margin-bottom:14px;
    padding:10px;
    border-radius:10px;
    background:rgba(255,0,90,.1);
    color:#ff6b9d;
    text-align:center;
}
.back{
    display:block;
    text-align:center;
    margin-top:16px;
    color:#aaa;
    text-decoration:none;
    font-size:14px;
}
</style>
</head>
<body>

<div class="auth-card">
    <div class="logo">ARVA</div>
    <h1>ساخت حساب جدید</h1>

    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}

    <form method="POST">
        <input type="hidden" name="csrf" value="{{ csrf }}">

        <label for="username">نام کاربری</label>
        <input
            id="username"
            name="username"
            type="text"
            minlength="3"
            maxlength="30"
            autocomplete="username"
            required
        >

        <label for="password">رمز عبور</label>
        <input
            id="password"
            name="password"
            type="password"
            minlength="8"
            autocomplete="new-password"
            required
        >

        <button type="submit">ساخت حساب</button>
    </form>

    <a class="back" href="/login">قبلاً حساب داری؟ ورود</a>
</div>

</body>
</html>
"""

@app.route("/register", methods=["GET", "POST"])
def register():

    if session.get("user_id"):
        return redirect(url_for("home"))

    if request.method == "POST":

        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 30:
            return render_template_string(
                REGISTER_PAGE,
                error="نام کاربری باید بین ۳ تا ۳۰ کاراکتر باشد.",
                csrf=csrf_token()
            )

        if len(password) < 8:
            return render_template_string(
                REGISTER_PAGE,
                error="رمز عبور باید حداقل ۸ کاراکتر باشد.",
                csrf=csrf_token()
            )

        connection = db()

        existing = connection.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            connection.close()
            return render_template_string(
                REGISTER_PAGE,
                error="این نام کاربری قبلاً استفاده شده است.",
                csrf=csrf_token()
            )

        password_hash = generate_password_hash(password)

        connection.execute(
            """
            INSERT INTO users (username, password_hash)
            VALUES (?, ?)
            """,
            (username, password_hash)
        )

        connection.commit()

        user = connection.execute(
            "SELECT id, username FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        connection.close()

        session.clear()

        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["csrf"] = token_urlsafe(32)
        session.permanent = True

        return redirect(url_for("home"))

    return render_template_string(
        REGISTER_PAGE,
        error=None,
        csrf=csrf_token()
    )

# =========================
# USER LOGIN
# =========================

LOGIN_USER_PAGE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARVA MUSIC — ورود</title>

<style>
*{box-sizing:border-box}

body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    padding:20px;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}

.auth-card{
    width:min(400px,100%);
    background:linear-gradient(145deg,#151515,#080808);
    border:1px solid rgba(255,0,90,.45);
    border-radius:22px;
    padding:32px 24px;
    box-shadow:
        0 20px 80px rgba(0,0,0,.7),
        0 0 40px rgba(255,0,90,.15);
}

.logo{
    text-align:center;
    color:#ff005a;
    font-size:32px;
    font-weight:900;
    letter-spacing:4px;
    margin-bottom:10px;
}

h1{
    text-align:center;
    font-size:22px;
    margin:0 0 24px;
}

label{
    display:block;
    margin:14px 0 7px;
    color:#ccc;
    font-size:14px;
}

input{
    width:100%;
    padding:13px 14px;
    border-radius:12px;
    border:1px solid #333;
    background:#0d0d0d;
    color:white;
    outline:none;
}

input:focus{
    border-color:#ff005a;
    box-shadow:0 0 12px rgba(255,0,90,.15);
}

button{
    width:100%;
    margin-top:22px;
    padding:14px;
    border:0;
    border-radius:12px;
    background:#ff005a;
    color:white;
    font-weight:800;
    cursor:pointer;
}

.error{
    margin-bottom:14px;
    padding:10px;
    border-radius:10px;
    background:rgba(255,0,90,.1);
    color:#ff6b9d;
    text-align:center;
}

.back{
    display:block;
    text-align:center;
    margin-top:16px;
    color:#aaa;
    text-decoration:none;
    font-size:14px;
}
</style>
</head>

<body>

<div class="auth-card">

    <div class="logo">ARVA</div>

    <h1>ورود به حساب</h1>

    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}

    <form method="POST">

        <input type="hidden" name="csrf" value="{{ csrf }}">

        <label for="username">نام کاربری</label>

        <input
            id="username"
            name="username"
            type="text"
            maxlength="30"
            autocomplete="username"
            required
        >

        <label for="password">رمز عبور</label>

        <input
            id="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
        >

        <button type="submit">
            ورود
        </button>

    </form>

    <a class="back" href="/register">
        حساب نداری؟ ساخت حساب جدید
    </a>

</div>

</body>
</html>
"""

@app.route("/login", methods=["GET", "POST"])
def user_login():

    if session.get("user_id"):
        return redirect(url_for("home"))

    ip = client_ip()

    if is_locked(ip):
        return render_template_string(
            LOGIN_USER_PAGE,
            error="تلاش‌های ورود بیش از حد مجاز است. کمی بعد دوباره امتحان کنید.",
            csrf=csrf_token()
        )

    if request.method == "POST":

        check_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        connection = db()

        user = connection.execute(
            """
            SELECT id, username, password_hash
            FROM users
            WHERE username = ?
            """,
            (username,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            successful_login(ip)

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["csrf"] = token_urlsafe(32)
            session.permanent = True

            return redirect(url_for("home"))

        failed_login(ip)

        return render_template_string(
            LOGIN_USER_PAGE,
            error="نام کاربری یا رمز عبور اشتباه است.",
            csrf=csrf_token()
        )

    return render_template_string(
        LOGIN_USER_PAGE,
        error=None,
        csrf=csrf_token()
    )

# =========================
# USER LOGOUT
# =========================

@app.route("/logout")
def user_logout():

    session.pop("user_id", None)
    session.pop("username", None)
    session["csrf"] = token_urlsafe(32)

    return redirect(url_for("home"))

FRIENDS_PAGE = """
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ARVA MUSIC — رفقا</title>
<style>
*{box-sizing:border-box}
body{
    margin:0;
    background:#050505;
    color:white;
    font-family:Arial,sans-serif;
}
header{
    height:70px;
    padding:0 7%;
    display:flex;
    align-items:center;
    justify-content:space-between;
    border-bottom:1px solid #222;
    background:#090909;
}
.logo{
    font-size:23px;
    font-weight:900;
    letter-spacing:2px;
}
.logo span{color:#ff176d}
.back{
    color:#ff6c94;
    text-decoration:none;
    font-weight:bold;
}
main{
    width:min(700px,92%);
    margin:45px auto;
}
h1{font-size:32px}
.sub{
    color:#777;
    margin-bottom:25px;
}
.user{
    display:flex;
    align-items:center;
    gap:15px;
    padding:16px 18px;
    margin-bottom:10px;
    background:#101014;
    border:1px solid #24242a;
    border-radius:14px;
}
.number{
    width:34px;
    height:34px;
    display:flex;
    align-items:center;
    justify-content:center;
    border-radius:50%;
    background:#ff176d;
    font-weight:bold;
}
.username{
    font-size:16px;
    font-weight:bold;
}
.empty{
    padding:25px;
    text-align:center;
    color:#777;
    background:#101014;
    border-radius:14px;
}
</style>
</head>
<body>

<header>
<div class="logo">ARVA <span>MUSIC</span></div>
<a class="back" href="/admin">بازگشت به پنل</a>
</header>

<main>
<h1>رفقا 👥</h1>
<div class="sub">کاربران ثبت‌نام‌شده ARVA MUSIC</div>

{% if users %}
  {% for user in users %}
    <div class="user">
      <div class="number">{{ loop.index }}</div>
      <div class="username">{{ user["username"] }}</div>
    </div>
  {% endfor %}
{% else %}
  <div class="empty">هنوز کاربری ثبت‌نام نکرده است.</div>
{% endif %}

</main>
</body>
</html>
"""

@app.route("/admin/friends")
@admin_required
def admin_friends():
    connection = db()
    users = connection.execute("""
        SELECT id, username
        FROM users
        ORDER BY id DESC
    """).fetchall()
    connection.close()

    return render_template_string(
        FRIENDS_PAGE,
        users=users
    )

@app.route("/admin")
@admin_required
def admin():

    connection = db()

    songs = connection.execute("""
        SELECT id, title, artist
        FROM songs
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    return render_template_string(
        ADMIN_PAGE,
        songs=songs,
        csrf=csrf_token()
    )


# =========================
# UPLOAD
# =========================

@app.route("/admin/upload", methods=["POST"])
@admin_required
def upload():

    check_csrf()

    title = request.form.get("title", "").strip()
    artist = request.form.get("artist", "").strip()

    audio = request.files.get("audio")
    cover = request.files.get("cover")

    if not title or not artist or not audio:
        abort(400)

    if len(title) > 120 or len(artist) > 120:
        abort(400)

    if not allowed_file(
        audio.filename,
        ALLOWED_AUDIO
    ):
        abort(400)

    if cover and cover.filename:

        if not allowed_file(
            cover.filename,
            ALLOWED_IMAGES
        ):
            abort(400)

    audio_extension = audio.filename.rsplit(".", 1)[1].lower()

    audio_name = (
        uuid.uuid4().hex +
        "." +
        audio_extension
    )

    audio.save(
        AUDIO_DIR / audio_name
    )

    cover_name = None

    if cover and cover.filename:

        cover_extension = (
            cover.filename
            .rsplit(".", 1)[1]
            .lower()
        )

        cover_name = (
            uuid.uuid4().hex +
            "." +
            cover_extension
        )

        cover.save(
            COVER_DIR / cover_name
        )

    connection = db()

    connection.execute(
        """
        INSERT INTO songs
        (title, artist, audio_file, cover_file)
        VALUES (?, ?, ?, ?)
        """,
        (
            title,
            artist,
            audio_name,
            cover_name
        )
    )

    connection.commit()
    connection.close()

    return redirect(url_for("admin"))


# =========================
# DELETE
# =========================

@app.route("/admin/delete/<int:song_id>", methods=["POST"])
@admin_required
def delete_song(song_id):

    check_csrf()

    connection = db()

    song = connection.execute(
        """
        SELECT audio_file, cover_file
        FROM songs
        WHERE id = ?
        """,
        (song_id,)
    ).fetchone()

    if not song:
        connection.close()
        abort(404)

    connection.execute(
        "DELETE FROM songs WHERE id = ?",
        (song_id,)
    )

    connection.commit()
    connection.close()

    audio_path = AUDIO_DIR / song["audio_file"]

    if audio_path.exists():
        audio_path.unlink()

    if song["cover_file"]:

        cover_path = COVER_DIR / song["cover_file"]

        if cover_path.exists():
            cover_path.unlink()

    return redirect(url_for("admin"))


# =========================
# LOGOUT
# =========================

@app.route("/admin/logout")
def logout():

    session.clear()

    return redirect(url_for("home"))


# =========================
# SECURITY HEADERS
# =========================

@app.after_request
def security_headers(response):

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=()"
    )

    return response


# =========================
# START
# =========================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
