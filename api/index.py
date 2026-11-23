import os, re, hmac, hashlib, secrets, smtplib, ssl, mimetypes
from datetime import timedelta
from email.message import EmailMessage
from functools import wraps
import psycopg2, psycopg2.extras
from flask import (Flask, request, session, redirect, url_for, flash,
                   render_template_string, Response, abort, get_flashed_messages)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me")
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                  SESSION_COOKIE_SECURE=bool(os.environ.get("VERCEL")),
                  PERMANENT_SESSION_LIFETIME=timedelta(days=14),
                  MAX_CONTENT_LENGTH=int(4.4 * 1024 * 1024))  # Vercel body limit ~4.5MB
MAX_MB = 4

def db():
    return psycopg2.connect(os.environ["DATABASE_URL"], cursor_factory=psycopg2.extras.RealDictCursor)

def q(sql, args=(), one=False, commit=False):
    con = db()
    try:
        with con, con.cursor() as c:
            c.execute(sql, args)
            if c.description:
                return c.fetchone() if one else c.fetchall()
    finally:
        con.close()

def hsh(t): return hashlib.sha256(t.encode()).hexdigest()

def make_token(uid, purpose, hours):
    t = secrets.token_urlsafe(32)
    q("INSERT INTO tokens(user_id,token_hash,purpose,expires_at) VALUES(%s,%s,%s,now()+%s*interval '1 hour')",
      (uid, hsh(t), purpose, hours))
    return t

def use_token(t, purpose):
    r = q("UPDATE tokens SET used=TRUE WHERE token_hash=%s AND purpose=%s AND used=FALSE AND expires_at>now() RETURNING user_id",
          (hsh(t), purpose), one=True)
    return r["user_id"] if r else None

def send_mail(to, subject, body):
    m = EmailMessage()
    m["From"] = os.environ.get("MAIL_FROM", os.environ.get("SMTP_USER", ""))
    m["To"], m["Subject"] = to, subject
    m.set_content(body)
    host, port = os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587))
    if port == 465:
        s = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15)
    else:
        s = smtplib.SMTP(host, port, timeout=15); s.starttls(context=ssl.create_default_context())
    with s:
        s.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"])
        s.send_message(m)

def base_url(): return os.environ.get("APP_URL", request.host_url).rstrip("/")

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"): return redirect(url_for("login"))
        return f(*a, **k)
    return w

def csrf_ok():
    return hmac.compare_digest(request.form.get("csrf", ""), session.get("csrf", ""))

@app.before_request
def guard():
    session.setdefault("csrf", secrets.token_hex(16))
    if request.method == "POST" and not csrf_ok(): abort(400, "Bad CSRF token")

def kind_of(mime):
    return "image" if mime.startswith("image/") else "video" if mime.startswith("video/") else "file"

# ---------- templates ----------
LAYOUT = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title or 'YIM CLOUD STORAGE' }}</title>
<style>
:root{--bg:#f5f7fb;--card:#fff;--tx:#14213d;--mu:#667085;--pr:#4f46e5;--bd:#e4e7ec;--er:#d92d20;--ok:#12b76a}
@media(prefers-color-scheme:dark){:root{--bg:#0b1020;--card:#151b2e;--tx:#e8ecf5;--mu:#98a2b3;--bd:#27304a}}
*{box-sizing:border-box}body{margin:0;font:16px system-ui,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;display:flex;flex-direction:column}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--bd)}
.logo{font-weight:800;color:var(--pr);text-decoration:none;font-size:1.1rem}
main{flex:1;width:100%;max-width:1000px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:22px;max-width:420px;margin:30px auto}
h1,h2{margin:0 0 14px}label{display:block;font-size:.9rem;margin:12px 0 4px}
input[type=text],input[type=email],input[type=password]{width:100%;padding:11px;border:1px solid var(--bd);border-radius:9px;background:var(--bg);color:var(--tx);font-size:1rem}
.pw{position:relative}.pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--pr);cursor:pointer;font-size:.85rem}
.btn{display:inline-block;background:var(--pr);color:#fff;border:0;padding:11px 16px;border-radius:9px;cursor:pointer;font-size:1rem;text-decoration:none}
.btn.full{width:100%;margin-top:16px}.btn.sm{padding:6px 10px;font-size:.85rem}.btn.red{background:var(--er)}.btn.gray{background:var(--mu)}
a{color:var(--pr)}.mu{color:var(--mu);font-size:.9rem}.flash{padding:10px 14px;border-radius:9px;margin-bottom:12px;background:#eef2ff;color:#312e81}.flash.error{background:#fee4e2;color:#912018}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-top:14px}
.item{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden}
.thumb{height:120px;background:var(--bg);display:flex;align-items:center;justify-content:center;font-size:2.4rem}
.thumb img,.thumb video{width:100%;height:100%;object-fit:cover}.meta{padding:8px 10px;font-size:.85rem}
.meta b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.acts{display:flex;gap:6px;padding:0 10px 10px}
.tabs a{margin-right:8px;padding:5px 12px;border-radius:99px;text-decoration:none;border:1px solid var(--bd);font-size:.9rem}.tabs a.on{background:var(--pr);color:#fff}
.up{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
footer{text-align:center;padding:18px;color:var(--mu);font-size:.85rem;border-top:1px solid var(--bd)}
</style></head><body>
<header><a class="logo" href="/">☁️ YIM CLOUD STORAGE</a>
{% if session.uid %}<span><span class="mu">{{ session.uname }}</span> &nbsp;
<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn sm gray">Logout</button></form></span>{% endif %}</header>
<main>{% for c,m in get_flashed_messages(with_categories=true) %}<div class="flash {{c}}">{{m}}</div>{% endfor %}
{{ body|safe }}</main>
<footer>DEVELOPED BY SYMOH TECH</footer>
<script>document.querySelectorAll('.pw button').forEach(b=>b.onclick=()=>{const i=b.parentNode.querySelector('input');const s=i.type==='password';i.type=s?'text':'password';b.textContent=s?'Hide':'Show'})</script>
</body></html>"""

def page(body, title=None, **ctx):
    inner = render_template_string(body, **ctx)
    return render_template_string(LAYOUT, body=inner, title=title)

PW = """<div class="pw"><input type="password" name="{n}" id="{n}" required minlength="8" autocomplete="{a}"><button type="button">Show</button></div>"""
CSRF = '<input type="hidden" name="csrf" value="{{ session.csrf }}">'

# ---------- auth routes ----------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, e, p = request.form["username"].strip(), request.form["email"].strip().lower(), request.form["password"]
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", u): flash("Username: 3-30 letters, numbers, _ . -", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e): flash("Enter a valid email.", "error")
        elif len(p) < 8: flash("Password must be at least 8 characters.", "error")
        elif q("SELECT 1 FROM users WHERE lower(username)=lower(%s) OR email=%s", (u, e), one=True):
            flash("Username or email already in use.", "error")
        else:
            r = q("INSERT INTO users(username,email,password_hash) VALUES(%s,%s,%s) RETURNING id",
                  (u, e, generate_password_hash(p)), one=True)
            try:
                t = make_token(r["id"], "verify", 24)
                send_mail(e, "Verify your YIM CLOUD STORAGE account",
                          f"Hi {u},\n\nConfirm your email:\n{base_url()}/verify/{t}\n\nThis link expires in 24 hours.")
                flash("Account created! Check your email to verify it.")
            except Exception:
                flash("Account created, but the email could not be sent. Use 'Resend verification'.", "error")
            return redirect(url_for("login"))
    return page("""<div class="card"><h2>Create account</h2><form method="post">""" + CSRF + """
<label>Username</label><input type="text" name="username" required value="{{ request.form.username }}">
<label>Email</label><input type="email" name="email" required value="{{ request.form.email }}">
<label>Password</label>""" + PW.format(n="password", a="new-password") + """
<button class="btn full">Sign up</button></form>
<p class="mu">Have an account? <a href="/login">Log in</a></p></div>""", "Sign up")

@app.route("/verify/<t>")
def verify(t):
    uid = use_token(t, "verify")
    if uid:
        q("UPDATE users SET verified=TRUE WHERE id=%s", (uid,)); flash("Email verified! You can log in now.")
    else: flash("Invalid or expired verification link.", "error")
    return redirect(url_for("login"))

@app.route("/resend", methods=["GET", "POST"])
def resend():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        u = q("SELECT id,username FROM users WHERE email=%s AND verified=FALSE", (e,), one=True)
        if u:
            try:
                t = make_token(u["id"], "verify", 24)
                send_mail(e, "Verify your YIM CLOUD STORAGE account", f"Confirm your email:\n{base_url()}/verify/{t}")
            except Exception: pass
        flash("If that account needs verification, a new email was sent."); return redirect(url_for("login"))
    return page("""<div class="card"><h2>Resend verification</h2><form method="post">""" + CSRF + """
<label>Email</label><input type="email" name="email" required><button class="btn full">Send</button></form></div>""")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        idf, p = request.form["identifier"].strip(), request.form["password"]
        u = q("SELECT * FROM users WHERE lower(username)=lower(%s) OR email=lower(%s)", (idf, idf), one=True)
        if not u or not check_password_hash(u["password_hash"], p): flash("Wrong username/email or password.", "error")
        elif not u["verified"]: flash("Please verify your email first (see 'Resend verification').", "error")
        else:
            session.clear(); session.permanent = True
            session.update(uid=u["id"], uname=u["username"], csrf=secrets.token_hex(16))
            return redirect(url_for("home"))
    return page("""<div class="card"><h2>Welcome back</h2><form method="post">""" + CSRF + """
<label>Username or email</label><input type="text" name="identifier" required>
<label>Password</label>""" + PW.format(n="password", a="current-password") + """
<button class="btn full">Log in</button></form>
<p class="mu"><a href="/forgot">Forgot password?</a> · <a href="/resend">Resend verification</a></p>
<p class="mu">New here? <a href="/register">Create account</a></p></div>""", "Log in")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        u = q("SELECT id FROM users WHERE email=%s", (e,), one=True)
        if u:
            try:
                t = make_token(u["id"], "reset", 1)
                send_mail(e, "Reset your YIM CLOUD STORAGE password",
                          f"Reset your password (valid 1 hour):\n{base_url()}/reset/{t}\n\nIf you didn't request this, ignore this email.")
            except Exception: pass
        flash("If that email is registered, a reset link has been sent."); return redirect(url_for("login"))
    return page("""<div class="card"><h2>Forgot password</h2><form method="post">""" + CSRF + """
<label>Email</label><input type="email" name="email" required><button class="btn full">Send reset link</button></form></div>""")

@app.route("/reset/<t>", methods=["GET", "POST"])
def reset(t):
    ok = q("SELECT 1 FROM tokens WHERE token_hash=%s AND purpose='reset' AND used=FALSE AND expires_at>now()", (hsh(t),), one=True)
    if not ok: flash("Invalid or expired reset link.", "error"); return redirect(url_for("forgot"))
    if request.method == "POST":
        p = request.form["password"]
        if len(p) < 8: flash("Password must be at least 8 characters.", "error")
        else:
            uid = use_token(t, "reset")
            if uid:
                q("UPDATE users SET password_hash=%s, verified=TRUE WHERE id=%s", (generate_password_hash(p), uid))
                flash("Password updated. Please log in."); return redirect(url_for("login"))
    return page("""<div class="card"><h2>New password</h2><form method="post">""" + CSRF + """
<label>New password</label>""" + PW.format(n="password", a="new-password") + """<button class="btn full">Reset password</button></form></div>""")

# ---------- storage ----------
def human(n):
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

@app.route("/")
@login_required
def home():
    k = request.args.get("k", "all")
    sql, args = "SELECT id,name,mime,kind,size,created_at FROM files WHERE user_id=%s", [session["uid"]]
    if k in ("image", "video", "file"): sql += " AND kind=%s"; args.append(k)
    rows = q(sql + " ORDER BY created_at DESC", args)
    used = q("SELECT COALESCE(sum(size),0) s FROM files WHERE user_id=%s", (session["uid"],), one=True)["s"]
    return page("""<h2>My files</h2>
<form class="up" method="post" action="/upload" enctype="multipart/form-data">""" + CSRF + """
<input type="file" name="files" multiple required><button class="btn">Upload</button>
<span class="mu">Max {{ mb }} MB per upload · Used {{ used }}</span></form>
<p class="tabs" style="margin-top:16px">{% for t,l in [('all','All'),('image','Images'),('video','Videos'),('file','Files')] %}<a class="{{ 'on' if k==t }}" href="/?k={{t}}">{{l}}</a>{% endfor %}</p>
{% if not rows %}<p class="mu">Nothing here yet. Upload your first file!</p>{% endif %}
<div class="grid">{% for r in rows %}<div class="item"><div class="thumb">
{% if r.kind=='image' %}<img loading="lazy" src="/f/{{r.id}}" alt="">{% elif r.kind=='video' %}<video preload="metadata" src="/f/{{r.id}}#t=0.5" controls></video>{% else %}📄{% endif %}</div>
<div class="meta"><b title="{{r.name}}">{{r.name}}</b><span class="mu">{{ hs(r.size) }}</span></div>
<div class="acts"><a class="btn sm" href="/f/{{r.id}}?dl=1">Download</a>
<form method="post" action="/delete/{{r.id}}" onsubmit="return confirm('Delete this file?')">""" + CSRF + """<button class="btn sm red">Delete</button></form></div></div>{% endfor %}</div>""",
                "My files", rows=rows, k=k, mb=MAX_MB, used=human(used), hs=human)

@app.errorhandler(413)
def too_big(e):
    flash(f"Upload too large. Max {MAX_MB} MB per upload on Vercel.", "error"); return redirect(url_for("home"))

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    n = 0
    for f in request.files.getlist("files"):
        data = f.read()
        if not f.filename or not data: continue
        mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
        q("INSERT INTO files(user_id,name,mime,kind,size,data) VALUES(%s,%s,%s,%s,%s,%s)",
          (session["uid"], os.path.basename(f.filename)[:200], mime, kind_of(mime), len(data), psycopg2.Binary(data)))
        n += 1
    flash(f"Uploaded {n} file(s)."); return redirect(url_for("home"))

@app.route("/f/<int:fid>")
@login_required
def serve(fid):
    m = q("SELECT name,mime,size FROM files WHERE id=%s AND user_id=%s", (fid, session["uid"]), one=True)
    if not m: abort(404)
    size, start, end, status = m["size"], 0, m["size"] - 1, 200
    rg = re.fullmatch(r"bytes=(\d*)-(\d*)", request.headers.get("Range", ""))
    if rg and (rg.group(1) or rg.group(2)):
        if rg.group(1): start = int(rg.group(1)); end = int(rg.group(2)) if rg.group(2) else end
        else: start = max(0, size - int(rg.group(2)))
        end = min(end, size - 1); status = 206
    d = q("SELECT substring(data from %s for %s) AS d FROM files WHERE id=%s", (start + 1, end - start + 1, fid), one=True)["d"]
    h = {"Accept-Ranges": "bytes", "Content-Length": str(end - start + 1), "X-Content-Type-Options": "nosniff",
         "Cache-Control": "private, max-age=3600"}
    if status == 206: h["Content-Range"] = f"bytes {start}-{end}/{size}"
    safe = m["name"].replace('"', "")
    inline = m["mime"].startswith(("image/", "video/")) and m["mime"] != "image/svg+xml" and not request.args.get("dl")
    h["Content-Disposition"] = f'{"inline" if inline else "attachment"}; filename="{safe}"'
    return Response(bytes(d), status=status, mimetype=m["mime"] if inline else "application/octet-stream", headers=h)

@app.route("/delete/<int:fid>", methods=["POST"])
@login_required
def delete(fid):
    q("DELETE FROM files WHERE id=%s AND user_id=%s", (fid, session["uid"])); flash("File deleted.")
    return redirect(url_for("home"))
