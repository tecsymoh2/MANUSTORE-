from urllib.parse import parse_qsl, urlencode
import os, re, hmac, json, secrets, mimetypes, urllib.request, urllib.error
from datetime import timedelta, datetime, timezone
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
                  MAX_CONTENT_LENGTH=int(4.4 * 1024 * 1024))  # only the no-S3 fallback posts through Vercel
MAX_MB = 4

class FixPath:
    """Vercel gives Flask the function path (/api/index). vercel.json passes the real
    page path in ?__path=..., so restore it here."""
    def __init__(self, a): self.a = a
    def __call__(self, environ, start_response):
        p = environ.get("PATH_INFO", "")
        if p == "/api/index" or p.startswith("/api/index/"):
            rest, real = [], None
            for k, v in parse_qsl(environ.get("QUERY_STRING", ""), keep_blank_values=True):
                if k == "__path" and real is None: real = v
                else: rest.append((k, v))
            if real is not None:
                environ["PATH_INFO"] = "/" + real.lstrip("/")
                environ["QUERY_STRING"] = urlencode(rest)
        return self.a(environ, start_response)
app.wsgi_app = FixPath(app.wsgi_app)

@app.errorhandler(500)
def server_error(e):
    app.logger.exception("Server error")
    detail = f"<p>{type(e.original_exception).__name__}: {e.original_exception}</p>" if os.environ.get("DEBUG") and getattr(e, "original_exception", None) else ""
    return f"<h3>Something went wrong</h3>{detail}<p><a href='/'>Go home</a></p>", 500

@app.errorhandler(404)
def not_found(e):
    return f'<h3>Page not found</h3><p>Path seen by server: {request.path}</p><p><a href="/">Go home</a></p>', 404

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

def neon_auth(path, payload):
    """Call Neon Auth (Better Auth) REST API. Returns (status, json)."""
    base = os.environ["NEON_AUTH_URL"].rstrip("/")
    req = urllib.request.Request(base + path, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Origin": base_url()})
    try:
        with urllib.request.urlopen(req, timeout=20) as r: code, body = r.status, r.read()
    except urllib.error.HTTPError as e: code, body = e.code, e.read()
    except Exception: return 0, {"message": "Could not reach the sign-in service. Try again."}
    try: d = json.loads(body or b"{}")
    except ValueError: d = {}
    return code, d if isinstance(d, dict) else {}

def emsg(d): return d.get("message") or "Something went wrong. Please try again."

def base_url(): return os.environ.get("APP_URL", request.host_url).rstrip("/")

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("uid"): return redirect(url_for("login"))
        return f(*a, **k)
    return w

def csrf_ok():
    return hmac.compare_digest(request.form.get("csrf") or request.headers.get("X-CSRF", ""), session.get("csrf", ""))

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
:root{--bg:#f3f4f8;--card:#fff;--tx:#14152b;--mu:#6b6f8a;--pr:#5b4bff;--bd:#e4e7ec;--er:#d92d20;--ok:#12b76a}
@media(prefers-color-scheme:dark){:root{--bg:#0e0f1d;--card:#171829;--tx:#eceeff;--mu:#8e92b0;--bd:#272944;--pr:#8b7dff}}
*{box-sizing:border-box}body{margin:0;font:16px system-ui,sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;display:flex;flex-direction:column}
header{display:flex;justify-content:space-between;align-items:center;padding:14px 20px;background:var(--card);border-bottom:1px solid var(--bd)}
.logo{font-weight:800;color:var(--pr);text-decoration:none;font-size:1.1rem}
main{flex:1;width:100%;max-width:1000px;margin:0 auto;padding:20px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:22px;max-width:420px;margin:30px auto}
h1,h2{margin:0 0 14px}label{display:block;font-size:.9rem;margin:12px 0 4px}
input[type=text],input[type=email],input[type=password]{width:100%;padding:11px;border:1px solid var(--bd);border-radius:9px;background:var(--bg);color:var(--tx);font-size:1rem}
.pw{position:relative}.pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--pr);cursor:pointer;font-size:.85rem}
.btn{display:inline-block;background:var(--pr);color:#fff;border:0;padding:11px 18px;border-radius:999px;cursor:pointer;font-size:1rem;text-decoration:none}
.btn.full{width:100%;margin-top:16px}.btn.sm{padding:6px 10px;font-size:.85rem}.btn.red{background:var(--er)}.btn.gray{background:var(--mu)}
a{color:var(--pr)}.mu{color:var(--mu);font-size:.9rem}.flash{padding:10px 14px;border-radius:9px;margin-bottom:12px;background:#eef2ff;color:#312e81}.flash.error{background:#fee4e2;color:#912018}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:12px;margin-top:14px}
.item{background:var(--card);border:1px solid var(--bd);border-radius:12px;overflow:hidden}
.thumb{height:120px;background:var(--bg);display:flex;align-items:center;justify-content:center;font-size:2.4rem}
.thumb img,.thumb video{width:100%;height:100%;object-fit:cover}.meta{padding:8px 10px;font-size:.85rem}
.meta b{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.acts{display:flex;gap:6px;padding:0 10px 10px}
.tabs a{margin-right:8px;padding:5px 12px;border-radius:99px;text-decoration:none;border:1px solid var(--bd);font-size:.9rem}.tabs a.on{background:var(--pr);color:#fff}
.bar{height:10px;border-radius:5px;background:var(--bd);overflow:hidden;margin:8px 0}.bar i{display:block;height:100%;background:var(--pr)}.sl{width:100%;font-size:.75rem;padding:5px;margin-top:6px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx)}.acts form{display:inline}
.up{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
footer{text-align:center;padding:18px;color:var(--mu);font-size:.85rem;border-top:1px solid var(--bd)}
</style></head><body{% if full %} class="app"{% endif %}>
{% if full %}{{ body|safe }}{% else %}<header><a class="logo" href="/">☁️ YIM CLOUD STORAGE</a>
{% if session.uid %}<span><span class="mu">{{ session.uname }}</span> &nbsp;
<form method="post" action="/logout" style="display:inline"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn sm gray">Logout</button></form></span>{% endif %}</header>
<main>{% for c,m in get_flashed_messages(with_categories=true) %}<div class="flash {{c}}">{{m}}</div>{% endfor %}
{{ body|safe }}</main>
<footer>DEVELOPED BY SYMOH TECH</footer>{% endif %}
<script>document.querySelectorAll('.pw button').forEach(b=>b.onclick=()=>{const i=b.parentNode.querySelector('input');const s=i.type==='password';i.type=s?'text':'password';b.textContent=s?'Hide':'Show'})</script>
</body></html>"""

def page(body, title=None, full=False, **ctx):
    inner = render_template_string(body, **ctx)
    return render_template_string(LAYOUT, body=inner, title=title, full=full)

PW = """<div class="pw"><input type="password" name="{n}" id="{n}" required minlength="8" autocomplete="{a}"><button type="button">Show</button></div>"""
CSRF = '<input type="hidden" name="csrf" value="{{ session.csrf }}">'

# ---------- auth routes (Neon Auth handles passwords, emails and codes) ----------
def uniq_username(base):
    base = re.sub(r"[^A-Za-z0-9_.-]", "", base)[:24] or "user"
    n = base
    while q("SELECT 1 FROM users WHERE lower(username)=lower(%s)", (n,), one=True): n = base + secrets.token_hex(2)
    return n

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
            code, d = neon_auth("/sign-up/email", {"name": u, "email": e, "password": p})
            if code >= 400 or code == 0: flash(emsg(d), "error")
            else:
                q("INSERT INTO users(username,email,auth_id,verified) VALUES(%s,%s,%s,FALSE) ON CONFLICT DO NOTHING",
                  (u, e, (d.get("user") or {}).get("id")))
                flash("Account created! We emailed you a verification code.")
                return redirect(url_for("verify", email=e))
    return page("""<div class="card"><h2>Create account</h2><form method="post">""" + CSRF + """
<label>Username</label><input type="text" name="username" required value="{{ request.form.username }}">
<label>Email</label><input type="email" name="email" required value="{{ request.form.email }}">
<label>Password</label>""" + PW.format(n="password", a="new-password") + """
<button class="btn full">Sign up</button></form>
<p class="mu">Have an account? <a href="/login">Log in</a></p></div>""", "Sign up")

@app.route("/verify", methods=["GET", "POST"])
def verify():
    email = (request.values.get("email") or "").strip().lower()
    if request.method == "POST":
        if request.form.get("resend"):
            neon_auth("/email-otp/send-verification-otp", {"email": email, "type": "email-verification"})
            flash("A new code was sent if that account needs verification.")
        else:
            code, d = neon_auth("/email-otp/verify-email", {"email": email, "otp": request.form["otp"].strip()})
            if code == 200:
                q("UPDATE users SET verified=TRUE WHERE email=%s", (email,))
                flash("Email verified! You can log in now."); return redirect(url_for("login"))
            flash(emsg(d), "error")
    return page("""<div class="card"><h2>Verify your email</h2><p class="mu">Enter the code we emailed you.</p><form method="post">""" + CSRF + """
<label>Email</label><input type="email" name="email" required value="{{ email }}">
<label>Verification code</label><input type="text" name="otp" inputmode="numeric" autocomplete="one-time-code" maxlength="10">
<button class="btn full">Verify</button>
<button class="btn full gray" name="resend" value="1" formnovalidate>Send a new code</button></form></div>""", "Verify email", email=email)

@app.route("/resend")
def resend(): return redirect(url_for("verify"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        idf, p = request.form["identifier"].strip(), request.form["password"]
        u = q("SELECT * FROM users WHERE lower(username)=lower(%s) OR email=lower(%s)", (idf, idf), one=True)
        email = u["email"] if u else idf.lower()
        code, d = neon_auth("/sign-in/email", {"email": email, "password": p})
        if code == 200 and d.get("user"):
            if not u:  # account created in Neon Auth elsewhere: create the local profile
                nm = uniq_username(d["user"].get("name") or email.split("@")[0])
                u = q("INSERT INTO users(username,email,auth_id,verified) VALUES(%s,%s,%s,TRUE) RETURNING id,username",
                      (nm, email, d["user"].get("id")), one=True)
            else: q("UPDATE users SET verified=TRUE WHERE id=%s", (u["id"],))
            session.clear(); session.permanent = True
            session.update(uid=u["id"], uname=u["username"], csrf=secrets.token_hex(16))
            return redirect(url_for("home"))
        if code == 403 or d.get("code") == "EMAIL_NOT_VERIFIED":
            neon_auth("/email-otp/send-verification-otp", {"email": email, "type": "email-verification"})
            flash("Please verify your email — we sent you a new code."); return redirect(url_for("verify", email=email))
        flash("Wrong username/email or password." if code in (400, 401) else emsg(d), "error")
    return page("""<div class="card"><h2>Welcome back</h2><form method="post">""" + CSRF + """
<label>Username or email</label><input type="text" name="identifier" required>
<label>Password</label>""" + PW.format(n="password", a="current-password") + """
<button class="btn full">Log in</button></form>
<p class="mu"><a href="/forgot">Forgot password?</a> · <a href="/verify">Enter verification code</a></p>
<p class="mu">New here? <a href="/register">Create account</a></p></div>""", "Log in")

@app.route("/logout", methods=["POST"])
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        e = request.form["email"].strip().lower()
        neon_auth("/forget-password/email-otp", {"email": e})
        flash("If that email is registered, we sent a reset code."); return redirect(url_for("reset", email=e))
    return page("""<div class="card"><h2>Forgot password</h2><form method="post">""" + CSRF + """
<label>Email</label><input type="email" name="email" required><button class="btn full">Send reset code</button></form></div>""")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    email = (request.values.get("email") or "").strip().lower()
    if request.method == "POST":
        p = request.form["password"]
        if len(p) < 8: flash("Password must be at least 8 characters.", "error")
        else:
            code, d = neon_auth("/email-otp/reset-password", {"email": email, "otp": request.form["otp"].strip(), "password": p})
            if code == 200: flash("Password updated. Please log in."); return redirect(url_for("login"))
            flash(emsg(d), "error")
    return page("""<div class="card"><h2>Reset password</h2><form method="post">""" + CSRF + """
<label>Email</label><input type="email" name="email" required value="{{ email }}">
<label>Reset code</label><input type="text" name="otp" inputmode="numeric" autocomplete="one-time-code" required>
<label>New password</label>""" + PW.format(n="password", a="new-password") + """<button class="btn full">Reset password</button></form></div>""", "Reset password", email=email)

# ---------- storage ----------
S3_ON = bool(os.environ.get("S3_BUCKET") and os.environ.get("S3_KEY_ID"))
CAP = float(os.environ.get("STORAGE_CAP_GB", 5)) * 2**30
_s3 = None

def s3():
    global _s3
    if _s3 is None:
        import boto3
        from botocore.config import Config
        _s3 = boto3.client("s3", region_name=os.environ.get("S3_REGION", "us-east-2"),
                           endpoint_url=os.environ.get("S3_ENDPOINT") or None,
                           aws_access_key_id=os.environ["S3_KEY_ID"], aws_secret_access_key=os.environ["S3_SECRET"],
                           config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))
    return _s3

def presign(op, key, secs=3600, **extra):
    return s3().generate_presigned_url(op, Params={"Bucket": os.environ["S3_BUCKET"], "Key": key, **extra}, ExpiresIn=secs)

def human(n):
    n = float(n)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024: return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} TB"

def used_bytes(uid):
    return int(q("SELECT COALESCE(sum(size),0) s FROM files WHERE user_id=%s AND ready", (uid,), one=True)["s"])

def own(fid):
    r = q("SELECT * FROM files WHERE id=%s AND user_id=%s", (fid, session["uid"]), one=True)
    if not r: abort(404)
    return r

def send_row(fid, dl=False):
    m = q("SELECT name,mime,size,s3_key FROM files WHERE id=%s", (fid,), one=True)
    safe = re.sub(r"[^\w. -]", "_", m["name"]) or "file"
    inline = m["mime"].startswith(("image/", "video/", "audio/")) and m["mime"] != "image/svg+xml" and not dl
    disp = f'{"inline" if inline else "attachment"}; filename="{safe}"'
    mime = m["mime"] if inline else "application/octet-stream"
    if m["s3_key"]:
        return redirect(presign("get_object", m["s3_key"], 3600, ResponseContentDisposition=disp, ResponseContentType=mime), 302)
    size, start, end, status = m["size"], 0, m["size"] - 1, 200
    rg = re.fullmatch(r"bytes=(\d*)-(\d*)", request.headers.get("Range", ""))
    if rg and (rg.group(1) or rg.group(2)):
        if rg.group(1): start = int(rg.group(1)); end = int(rg.group(2)) if rg.group(2) else end
        else: start = max(0, size - int(rg.group(2)))
        end = min(end, size - 1); status = 206
    d = q("SELECT substring(data from %s for %s) AS d FROM files WHERE id=%s", (start + 1, end - start + 1, fid), one=True)["d"]
    h = {"Accept-Ranges": "bytes", "Content-Length": str(end - start + 1), "X-Content-Type-Options": "nosniff",
         "Content-Disposition": disp, "Content-Security-Policy": "sandbox"}
    if status == 206: h["Content-Range"] = f"bytes {start}-{end}/{size}"
    return Response(bytes(d), status=status, mimetype=mime, headers=h)

DASH = r"""<style>
body.app{display:block}.ib{background:none;border:0;border-radius:50%;width:40px;height:40px;font-size:1.1rem;cursor:pointer;color:var(--tx)}.ib:hover{background:var(--bg)}
.tb,#sb2{position:sticky;top:0;z-index:25;display:flex;align-items:center;gap:10px;padding:8px 16px;height:57px;background:var(--card);border-bottom:1px solid var(--bd)}
#sb2{position:fixed;left:0;right:0;display:none}.tb .logo{white-space:nowrap}.sr{flex:1;max-width:620px;margin:0 auto}.sr input{border:0;border-radius:999px;padding:11px 18px}
.av{list-style:none;width:36px;height:36px;border-radius:50%;background:var(--pr);color:#fff;display:grid;place-items:center;font-weight:700;cursor:pointer}.me{position:relative}.pop{position:absolute;right:0;top:44px;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:12px;min-width:150px;box-shadow:0 8px 24px #0003}
.sb{position:fixed;top:57px;left:0;bottom:0;width:230px;padding:12px 12px 0;overflow:auto}.sb a{display:flex;gap:12px;padding:11px 16px;border-radius:0 999px 999px 0;color:var(--tx);text-decoration:none}.sb a.on{background:color-mix(in srgb,var(--pr) 16%,transparent);color:var(--pr);font-weight:600}
.meter{padding:16px}.ct{margin-left:230px;padding:14px 20px 90px}.gh{margin:20px 0 8px;font-weight:600}.g{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:4px}
.t{position:relative;aspect-ratio:1;background:var(--bd);border-radius:8px;overflow:hidden;cursor:pointer}.t img,.t video{width:100%;height:100%;object-fit:cover;display:block}
.t .ck{position:absolute;top:6px;left:6px;width:24px;height:24px;border-radius:50%;border:2px solid #fff;background:#0005;color:#fff;display:grid;place-items:center;font-size:14px;opacity:0}.t:hover .ck,.sm .ck{opacity:1}
.sel{outline:3px solid var(--pr);outline-offset:-3px}.sel .ck{background:var(--pr);border-color:var(--pr)}.t .bd,.t .st{position:absolute;color:#fff;font-size:.85rem;text-shadow:0 1px 3px #000}.t .bd{bottom:6px;left:8px}.t .st{bottom:6px;right:8px;color:#fbbf24}
.doc{height:100%;display:grid;place-items:center;text-align:center;font-size:2rem;padding:8px}.doc small{display:block;font-size:.7rem;overflow:hidden;text-overflow:ellipsis;max-width:120px;white-space:nowrap}
.fab{position:fixed;right:18px;bottom:78px;width:56px;height:56px;border-radius:50%;font-size:1.6rem;display:none;padding:0;z-index:15;box-shadow:0 6px 20px #0004}
.mo{position:fixed;inset:0;background:#000b;z-index:50;display:none;align-items:center;justify-content:center}.mo.on{display:flex}.dl{background:var(--card);border-radius:18px;width:min(720px,94vw);max-height:92vh;overflow:auto;padding:18px}
.dz{border:2px dashed var(--bd);border-radius:14px;padding:24px;text-align:center;cursor:pointer;color:var(--mu);display:block}.qr{display:flex;gap:10px;align-items:center;padding:8px 0;border-bottom:1px solid var(--bd)}
.qt{width:54px;height:54px;border-radius:8px;overflow:hidden;background:var(--bd);flex:none;display:grid;place-items:center}.qt img,.qt video{width:100%;height:100%;object-fit:cover}.qm{flex:1;min-width:0}.qn{display:flex;align-items:center;gap:4px}
.qn input{padding:6px 8px;border:1px solid var(--bd);border-radius:8px;background:var(--bg);color:var(--tx);min-width:0;flex:1}.ss{font-size:.8rem;color:var(--mu)}.pb{height:4px;background:var(--bd);border-radius:2px;margin-top:4px}.pb i{display:block;height:100%;width:0;background:var(--pr);border-radius:2px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}.chip{border:1px solid var(--bd);background:var(--card);color:var(--tx);border-radius:999px;padding:6px 12px;cursor:pointer}.chip.on{background:var(--pr);color:#fff;border-color:var(--pr)}
select{padding:8px;border-radius:8px;border:1px solid var(--bd);background:var(--bg);color:var(--tx)}.cw{position:relative;display:inline-block;touch-action:none;max-width:100%}#ec{max-width:100%;max-height:44vh;display:block}
#cr{position:absolute;border:2px solid #fff;box-shadow:0 0 0 9999px #0008;display:none;pointer-events:none}
#lb{position:fixed;inset:0;background:#000;z-index:60;display:none;flex-direction:column;color:#fff}#lb.on{display:flex}#lbm{flex:1;display:flex;align-items:center;justify-content:center;min-height:0}#lbm img,#lbm video{max-width:100%;max-height:100%;object-fit:contain}
.lbt{display:flex;align-items:center;gap:4px;padding:8px 12px}.lbt .ib{color:#fff}.lbt .ib:hover{background:#fff2}.nv{position:absolute;top:50%;background:#fff2;color:#fff}#pv{left:10px}#nx{right:10px}
.ts{position:fixed;left:50%;bottom:90px;transform:translateX(-50%);background:#222;color:#fff;padding:10px 16px;border-radius:8px;z-index:99}.emp{text-align:center;color:var(--mu);padding:70px 0}.ft{text-align:center;color:var(--mu);font-size:.85rem;margin-top:40px}
@media(max-width:800px){.sb{top:auto;height:58px;width:100%;display:flex;padding:0;background:var(--card);border-top:1px solid var(--bd);z-index:20}.sb a{flex:1;flex-direction:column;align-items:center;gap:0;font-size:.68rem;border-radius:0;padding:6px 2px}.meter{display:none}.ct{margin-left:0}.logo span,#upb{display:none}.fab{display:block}.t .ck{opacity:1}}
</style>
<header class="tb"><a class="logo" href="/">☁️ <span>YIM CLOUD STORAGE</span></a>
<form class="sr" method="get"><input type="hidden" name="k" value="{{k}}"><input type="text" name="s" value="{{qs}}" placeholder="Search your files"></form>
<button class="btn" id="upb">⬆ Upload</button>
<details class="me"><summary class="av">{{ session.uname[:1]|upper }}</summary><div class="pop"><b>{{ session.uname }}</b><form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn sm gray" style="margin-top:8px">Logout</button></form></div></details></header>
<div id="sb2"><button class="ib" onclick="sel.clear();selUpdate()">✕</button><b id="sn" style="flex:1"></b>
{% if k=='trash' %}<button class="chip" onclick="bulk('restore')">♻ Restore</button><button class="chip" onclick="confirm('Delete forever?')&&bulk('purge')">Delete forever</button>
{% else %}<button class="ib" title="Favorite" onclick="bulk('fav')">★</button><button class="ib" title="Move to trash" onclick="bulk('trash')">🗑</button>{% endif %}</div>
<nav class="sb">{% for t,i,l in [('all','🖼','All'),('image','📷','Photos'),('video','🎬','Videos'),('file','📄','Files'),('fav','★','Favorites'),('trash','🗑','Trash')] %}<a class="{{ 'on' if k==t }}" href="/?k={{t}}"><span>{{i}}</span>{{l}}</a>{% endfor %}
<div class="meter"><div class="bar"><i style="width:{{ [100, used*100/cap]|min }}%"></i></div><span class="mu">{{ hs(used) }} of {{ hs(cap) }}</span></div></nav>
<div class="ct">
{% if k=='trash' and items %}<p class="mu">Items in Trash can be restored or deleted forever.</p>{% endif %}
{% if not items %}<div class="emp"><div style="font-size:3rem">☁️</div><p>{{ 'Nothing here yet.' if k!='all' or qs else 'Your cloud is empty. Upload photos, videos and files!' }}</p></div>{% endif %}
{% for lbl,rs in groups %}<div class="gh">{{lbl}}</div><div class="g">{% for r in rs %}<div class="t" data-i="{{r.i}}" data-id="{{r.id}}">
{% if r.kind=='image' %}<img loading="lazy" decoding="async" src="/f/{{r.id}}" alt="">{% elif r.kind=='video' %}<video muted preload="metadata" src="/f/{{r.id}}#t=0.1"></video><span class="bd">▶</span>{% else %}<div class="doc">📄<small>{{r.name}}</small></div>{% endif %}
<span class="ck">✓</span>{% if r.favorite %}<span class="st">★</span>{% endif %}</div>{% endfor %}</div>{% endfor %}
<div class="ft">DEVELOPED BY SYMOH TECH</div></div>
<button class="btn fab" id="fab">+</button>

<div class="mo" id="um"><div class="dl"><div class="row"><h3 style="margin:0;flex:1">Upload</h3><button class="ib" id="uc">✕</button></div>
<label class="dz" id="dz"><input type="file" id="pick" multiple hidden>Drop files here or <b style="color:var(--pr)">browse</b></label>
<div class="row"><span>Auto-shrink:</span><select id="qs"><option value="o">Original (no shrink)</option><option value="h">High (2560px / 1080p)</option><option value="m" selected>Medium (1920px / 720p)</option><option value="l">Low (1280px / 480p)</option></select></div>
<p class="ss" id="vn">Videos are re-encoded in your browser, so keep this tab open while they shrink.</p>
<div id="ql"></div><div class="row"><span class="ss" id="us" style="flex:1"></span><button class="btn" id="ug">Upload all</button></div></div></div>

<div class="mo" id="em"><div class="dl"><h3 style="margin-top:0">Edit image</h3><div style="text-align:center"><div class="cw" id="cw"><canvas id="ec"></canvas><div id="cr"></div></div></div>
<div class="row"><button class="chip" data-a="rl">⟲ Rotate</button><button class="chip" data-a="rr">⟳ Rotate</button><button class="chip" data-a="fh">⇋ Flip</button>
<button class="chip" data-r="0">Free</button><button class="chip" data-r="1">1:1</button><button class="chip" data-r="1.3333">4:3</button><button class="chip" data-r="1.7778">16:9</button><button class="chip" data-r="o">Original</button><button class="chip" id="ac">✂ Crop</button></div>
<div class="row"><label>Width <input id="rw" type="number" min="16" style="width:90px;padding:6px"> px</label>
<label>☀ <input type="range" id="fb" min="50" max="150" value="100"></label><label>◐ <input type="range" id="fc" min="50" max="150" value="100"></label><label>🎨 <input type="range" id="fs" min="0" max="200" value="100"></label></div>
<div class="row" style="justify-content:flex-end"><button class="btn gray" id="ex">Cancel</button><button class="btn gray" id="er">Reset</button><button class="btn" id="ed">Done</button></div></div></div>

<div id="lb"><div class="lbt"><button class="ib" id="lbc">←</button><b id="lbn" style="flex:1;overflow:hidden;white-space:nowrap;text-overflow:ellipsis"></b>
<button class="ib" id="lbf">☆</button><button class="ib" id="lbs" title="Share link">🔗</button><button class="ib" id="lbe" title="Rename">✎</button><button class="ib" id="lbd" title="Download">⬇</button><button class="ib" id="lbt" title="Trash">🗑</button></div>
<div id="lbm"></div><div class="lbt" style="justify-content:center"><span id="lbi" class="ss"></span></div><button class="ib nv" id="pv">‹</button><button class="ib nv" id="nx">›</button></div>

<script>const CSRF="{{ session.csrf }}",S3={{ s3|tojson }},ITEMS={{ items|tojson }},K="{{ k }}",FL={{ fl|tojson }};</script>
{% raw %}<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const post=(u,b,h={})=>fetch(u,{method:'POST',headers:{'X-CSRF':CSRF,...h},body:b});
const pj=(u,o)=>post(u,JSON.stringify(o),{'Content-Type':'application/json'});
const mo=(id,on)=>$(id).classList.toggle('on',on);
const hs=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(2)+' GB';
function toast(m){const t=document.createElement('div');t.className='ts';t.textContent=m;document.body.append(t);setTimeout(()=>t.remove(),3200)}
FL.forEach(f=>toast(f[1]));
const copy=u=>(navigator.clipboard?navigator.clipboard.writeText(u).then(()=>toast('Link copied')):Promise.reject()).catch(()=>prompt('Copy link',u));
/* selection */
const sel=new Set();
function selUpdate(){$('#sb2').style.display=sel.size?'flex':'none';$('#sn').textContent=sel.size+' selected';document.body.classList.toggle('sm',sel.size>0);$$('.t').forEach(t=>t.classList.toggle('sel',sel.has(+t.dataset.id)))}
$$('.t').forEach(t=>t.onclick=e=>{const id=+t.dataset.id;if(e.target.closest('.ck')||sel.size){sel.has(id)?sel.delete(id):sel.add(id);selUpdate()}else openLb(+t.dataset.i)});
async function bulk(a){await pj('/api/bulk',{ids:[...sel],action:a});location.reload()}
/* lightbox */
let li=0,dirty=0;
function openLb(i){if(i<0||i>=ITEMS.length)return;li=i;const x=ITEMS[i],m=$('#lbm');m.innerHTML='';
 if(x.k==='image'){const e=new Image();e.src='/f/'+x.id;m.append(e)}else if(x.k==='video'){const v=document.createElement('video');v.src='/f/'+x.id;v.controls=v.autoplay=v.playsInline=true;m.append(v)}
 else{m.innerHTML='<div style="text-align:center"><div style="font-size:4rem">📄</div><a class="btn" href="/f/'+x.id+'?dl=1">Download</a></div>'}
 $('#lbn').textContent=x.n;$('#lbf').textContent=x.f?'★':'☆';$('#lbi').textContent=x.s+' · '+x.d;mo('#lb',true)}
function closeLb(){mo('#lb',false);$('#lbm').innerHTML='';if(dirty)location.reload()}
$('#lbc').onclick=closeLb;$('#pv').onclick=()=>openLb(li-1);$('#nx').onclick=()=>openLb(li+1);
document.onkeydown=e=>{if(!$('#lb').classList.contains('on'))return;if(e.key==='Escape')closeLb();if(e.key==='ArrowLeft')openLb(li-1);if(e.key==='ArrowRight')openLb(li+1)};
let tx=0;$('#lbm').ontouchstart=e=>tx=e.touches[0].clientX;$('#lbm').ontouchend=e=>{const d=e.changedTouches[0].clientX-tx;if(Math.abs(d)>70)openLb(li+(d<0?1:-1))};
$('#lbf').onclick=async()=>{const x=ITEMS[li];await post('/fav/'+x.id);x.f=!x.f;$('#lbf').textContent=x.f?'★':'☆';dirty=1};
$('#lbs').onclick=async()=>{const x=ITEMS[li];if(!x.u){const r=await post('/share/'+x.id,new URLSearchParams({days:7}));x.u=(await r.json()).url;dirty=1}copy(x.u)};
$('#lbd').onclick=()=>location.href='/f/'+ITEMS[li].id+'?dl=1';
$('#lbt').onclick=async()=>{if(K==='trash'){if(!confirm('Delete forever?'))return;await post('/purge/'+ITEMS[li].id)}else await post('/trash/'+ITEMS[li].id);location.reload()};
$('#lbe').onclick=async()=>{const x=ITEMS[li],n=prompt('Rename',x.n);if(!n||n===x.n)return;const r=await pj('/api/rename/'+x.id,{name:n});if(r.ok){x.n=n;$('#lbn').textContent=n;dirty=1}};
/* ---- compression ---- */
const Q={o:null,h:{px:2560,v:.9,vh:1080,vb:5e6},m:{px:1920,v:.82,vh:720,vb:2.5e6},l:{px:1280,v:.7,vh:480,vb:1e6}};
const WEBP=document.createElement('canvas').toDataURL('image/webp').startsWith('data:image/webp')?'image/webp':'image/jpeg';
const EX={'image/webp':'.webp','image/jpeg':'.jpg','video/webm':'.webm','video/mp4':'.mp4'};
async function shrinkImg(blob,q){const bm=await createImageBitmap(blob),sc=Math.min(1,q.px/Math.max(bm.width,bm.height)),c=document.createElement('canvas');
 c.width=Math.round(bm.width*sc);c.height=Math.round(bm.height*sc);c.getContext('2d').drawImage(bm,0,0,c.width,c.height);
 const o=await new Promise(r=>c.toBlob(r,WEBP,q.v));return o&&o.size<blob.size?o:blob}
async function shrinkVid(blob,q,cb){
 if(!window.MediaRecorder||!HTMLCanvasElement.prototype.captureStream)return blob;
 const mt=['video/webm;codecs=vp9,opus','video/webm;codecs=vp8,opus','video/webm','video/mp4'].find(t=>MediaRecorder.isTypeSupported(t));if(!mt)return blob;
 const v=document.createElement('video');v.playsInline=true;v.src=URL.createObjectURL(blob);
 await new Promise((r,j)=>{v.onloadedmetadata=r;v.onerror=()=>j(new Error('Cannot read video'))});
 const sc=Math.min(1,q.vh/Math.min(v.videoWidth,v.videoHeight)),w=Math.round(v.videoWidth*sc/2)*2,h=Math.round(v.videoHeight*sc/2)*2;
 if(sc===1&&blob.size<3e6)return blob;
 const c=document.createElement('canvas');c.width=w;c.height=h;const x=c.getContext('2d'),out=c.captureStream(30);
 try{const ac=new AudioContext();await ac.resume();const d=ac.createMediaStreamDestination();ac.createMediaElementSource(v).connect(d);d.stream.getAudioTracks().forEach(t=>out.addTrack(t))}catch(e){}
 const rec=new MediaRecorder(out,{mimeType:mt,videoBitsPerSecond:q.vb}),ch=[];rec.ondataavailable=e=>e.data.size&&ch.push(e.data);
 const done=new Promise(r=>rec.onstop=r);rec.start(1000);let raf;
 const tick=()=>{x.drawImage(v,0,0,w,h);cb(v.currentTime/v.duration);raf=requestAnimationFrame(tick)};
 v.onended=()=>{cancelAnimationFrame(raf);rec.stop()};await v.play();tick();await done;
 const o=new Blob(ch,{type:mt.split(';')[0]});return o.size&&o.size<blob.size?o:blob}
/* ---- upload queue ---- */
const S=[];
function addFiles(fl){[...fl].forEach(f=>{const m=/^(.*?)(\.[^.]+)?$/.exec(f.name),k=f.type.startsWith('image/')?'image':f.type.startsWith('video/')?'video':'file';
 const st={blob:f,base:m[1]||'file',ext:m[2]||'',kind:k,shrink:true,orig:f.size};S.push(st);
 const r=document.createElement('div');r.className='qr';r.innerHTML='<div class="qt"></div><div class="qm"><div class="qn"><input class="nm"><span class="ex"></span></div><div class="ss"></div><div class="pb"><i></i></div></div><label class="ss"><input type="checkbox" class="sk" checked> shrink</label><button class="ib ed" title="Edit">✎</button><button class="ib rm" title="Remove">✕</button>';
 st.el=r;r.querySelector('.nm').value=st.base;r.querySelector('.nm').oninput=e=>st.base=e.target.value;r.querySelector('.sk').onchange=e=>st.shrink=e.target.checked;
 r.querySelector('.rm').onclick=()=>{S.splice(S.indexOf(st),1);r.remove()};
 const ed=r.querySelector('.ed');if(k!=='image'||/gif|svg/.test(f.type))ed.style.visibility='hidden';else ed.onclick=()=>openEd(st);
 if(k==='video')r.querySelector('.sk').parentNode.title='Shrinking videos takes about as long as the video';
 $('#ql').append(r);refresh(st)})}
function refresh(st){const r=st.el,q=r.querySelector('.qt');r.querySelector('.ex').textContent=st.ext;r.querySelector('.ss').textContent=hs(st.blob.size)+(st.blob.size!==st.orig?' (was '+hs(st.orig)+')':'');
 const u=URL.createObjectURL(st.blob);q.innerHTML='';if(st.kind==='image'){const i=new Image();i.src=u;q.append(i)}else if(st.kind==='video'){const v=document.createElement('video');v.src=u+'#t=0.1';v.muted=true;v.preload='metadata';q.append(v)}else q.textContent='📄'}
$('#pick').onchange=e=>{addFiles(e.target.files);e.target.value=''};
['dragover','drop'].forEach(n=>document.addEventListener(n,e=>{e.preventDefault();if(n==='drop'&&e.dataTransfer.files.length){mo('#um',true);addFiles(e.dataTransfer.files)}}));
$('#upb').onclick=$('#fab').onclick=()=>mo('#um',true);$('#uc').onclick=()=>{if(!S.some(s=>s.busy))mo('#um',false)};
function xhr(method,url,body,type,cb){return new Promise((ok,no)=>{const x=new XMLHttpRequest();x.open(method,url);if(type)x.setRequestHeader('Content-Type',type);x.setRequestHeader('X-CSRF',CSRF);
 x.upload.onprogress=e=>e.lengthComputable&&cb(e.loaded/e.total);
 x.onload=()=>x.status<300?ok():no(new Error((()=>{try{return JSON.parse(x.responseText).error}catch(e){return 'Upload failed'}})()));x.onerror=()=>no(new Error('Network error — check bucket CORS'));x.send(body)})}
async function upOne(b,name,cb){const type=b.type||'application/octet-stream';
 if(S3){const r=await pj('/api/presign',{name,type,size:b.size}),j=await r.json();if(!r.ok)throw new Error(j.error);
  await xhr('PUT',j.url,b,type,cb);const d=await post('/api/done/'+j.id);if(!d.ok)throw new Error('Could not finish upload')}
 else{const fd=new FormData();fd.append('file',b,name);await xhr('POST','/upload',fd,null,cb)}}
$('#ug').onclick=async()=>{if(!S.length)return;$('#ug').disabled=true;let ok=0;const q=Q[$('#qs').value];
 for(const st of S){if(st.done)continue;st.busy=1;const r=st.el,ss=r.querySelector('.ss'),bar=r.querySelector('.pb i');
  try{let b=st.blob;
   if(st.shrink&&q){ss.textContent='Shrinking…';if(st.kind==='image'&&!/gif|svg/.test(b.type))b=await shrinkImg(b,q);else if(st.kind==='video')b=await shrinkVid(b,q,p=>{ss.textContent='Shrinking video '+Math.round(p*100)+'%'})}
   const ext=b!==st.blob?(EX[b.type]||st.ext):st.ext,name=(st.base.trim()||'file')+ext;
   ss.textContent='Uploading '+hs(st.orig)+' → '+hs(b.size);await upOne(b,name,p=>bar.style.width=Math.round(p*100)+'%');
   bar.style.width='100%';ss.textContent='✓ Uploaded · '+hs(b.size);st.done=1;ok++}catch(e){ss.textContent='⚠ '+e.message}st.busy=0}
 $('#ug').disabled=false;if(ok){toast(ok+' file(s) uploaded');setTimeout(()=>location.reload(),800)}};
/* ---- image editor ---- */
let E=null,d0=null;const cw=$('#cw'),cv=$('#ec'),cr=$('#cr');
const flt=()=>`brightness(${$('#fb').value}%) contrast(${$('#fc').value}%) saturate(${$('#fs').value}%)`;
function load(st){const im=new Image();im.onload=()=>{const c=document.createElement('canvas');c.width=im.naturalWidth;c.height=im.naturalHeight;c.getContext('2d').drawImage(im,0,0);E={st,base:c,crop:null,asp:0};['#fb','#fc','#fs'].forEach(s=>$(s).value=100);draw();mo('#em',true)};im.src=URL.createObjectURL(st.blob)}
const openEd=load;
function draw(){const b=E.base;cv.width=b.width;cv.height=b.height;cv.getContext('2d').drawImage(b,0,0);cv.style.filter=flt();$('#rw').value=b.width;E.crop=null;cr.style.display='none'}
['#fb','#fc','#fs'].forEach(s=>$(s).oninput=()=>cv.style.filter=flt());
function tf(fn){const b=E.base,c=document.createElement('canvas'),x=fn(b,c)||c.getContext('2d');E.base=c;draw()}
function rot(d){tf((b,c)=>{c.width=b.height;c.height=b.width;const x=c.getContext('2d');x.translate(c.width/2,c.height/2);x.rotate(d*Math.PI/2);x.drawImage(b,-b.width/2,-b.height/2);return x})}
function flip(){tf((b,c)=>{c.width=b.width;c.height=b.height;const x=c.getContext('2d');x.translate(b.width,0);x.scale(-1,1);x.drawImage(b,0,0);return x})}
function setCrop(x,y,w,h){const r=cv.getBoundingClientRect();x=Math.max(0,x);y=Math.max(0,y);w=Math.min(w,r.width-x);h=Math.min(h,r.height-y);
 Object.assign(cr.style,{display:'block',left:x+'px',top:y+'px',width:w+'px',height:h+'px'});const s=cv.width/r.width;E.crop={x:x*s,y:y*s,w:w*s,h:h*s}}
cw.onpointerdown=e=>{const r=cv.getBoundingClientRect();d0={x:e.clientX-r.left,y:e.clientY-r.top,r};cw.setPointerCapture(e.pointerId)};
cw.onpointermove=e=>{if(!d0)return;const r=d0.r,x=Math.min(Math.max(e.clientX-r.left,0),r.width),y=Math.min(Math.max(e.clientY-r.top,0),r.height);let w=x-d0.x,h=y-d0.y;if(E.asp)h=(h<0?-1:1)*Math.abs(w)/E.asp;setCrop(Math.min(d0.x,d0.x+w),Math.min(d0.y,d0.y+h),Math.abs(w),Math.abs(h))};
cw.onpointerup=()=>d0=null;
$$('[data-a]').forEach(b=>b.onclick=()=>{const a=b.dataset.a;a==='rl'?rot(-1):a==='rr'?rot(1):flip()});
$$('[data-r]').forEach(b=>b.onclick=()=>{$$('[data-r]').forEach(x=>x.classList.remove('on'));b.classList.add('on');const v=b.dataset.r;E.asp=v==='o'?E.base.width/E.base.height:+v;
 if(!E.asp){E.crop=null;cr.style.display='none';return}const r=cv.getBoundingClientRect();let w=r.width,h=w/E.asp;if(h>r.height){h=r.height;w=h*E.asp}setCrop((r.width-w)/2,(r.height-h)/2,w,h)});
function applyCrop(){const k=E.crop;if(!k||k.w<8||k.h<8)return;tf((b,c)=>{c.width=Math.round(k.w);c.height=Math.round(k.h);const x=c.getContext('2d');x.drawImage(b,k.x,k.y,k.w,k.h,0,0,c.width,c.height);return x})}
$('#ac').onclick=applyCrop;$('#ex').onclick=()=>mo('#em',false);$('#er').onclick=()=>load(E.st);
$('#ed').onclick=()=>{applyCrop();const b=E.base,W=Math.max(16,+$('#rw').value||b.width),H=Math.round(b.height*W/b.width),c=document.createElement('canvas');c.width=W;c.height=H;
 const x=c.getContext('2d');x.filter=flt();x.drawImage(b,0,0,W,H);c.toBlob(o=>{E.st.blob=o;E.st.ext=EX[WEBP];refresh(E.st);mo('#em',false)},WEBP,.92)};
</script>{% endraw %}
"""

@app.route("/")
@login_required
def home():
    k, qs = request.args.get("k", "all"), request.args.get("s", "").strip()
    where, args = "user_id=%s AND ready", [session["uid"]]
    where += " AND trashed_at IS NOT NULL" if k == "trash" else " AND trashed_at IS NULL"
    if k == "fav": where += " AND favorite"
    if k in ("image", "video", "file"): where += " AND kind=%s"; args.append(k)
    if qs: where += " AND name ILIKE %s"; args.append(f"%{qs}%")
    rows = q(f"SELECT id,name,kind,size,favorite,share_slug,created_at FROM files WHERE {where} ORDER BY created_at DESC", args)
    used, base = used_bytes(session["uid"]), base_url()
    today = datetime.now(timezone.utc).date()
    groups, items = [], []
    for r in rows:
        d = r["created_at"].date()
        lbl = "Today" if d == today else "Yesterday" if d == today - timedelta(days=1) else d.strftime("%a, %d %b %Y")
        r["i"] = len(items)
        items.append({"id": r["id"], "n": r["name"], "k": r["kind"], "s": human(r["size"]), "f": bool(r["favorite"]),
                      "u": f"{base}/s/{r['share_slug']}" if r["share_slug"] else "", "d": d.isoformat()})
        if not groups or groups[-1][0] != lbl: groups.append((lbl, []))
        groups[-1][1].append(r)
    return page(DASH, "YIM CLOUD STORAGE", full=True, groups=groups, items=items, k=k, qs=qs, used=used, cap=CAP,
                hs=human, s3=S3_ON, fl=get_flashed_messages(with_categories=True))

@app.route("/api/bulk", methods=["POST"])
@login_required
def bulk():
    j = request.get_json(silent=True) or {}
    ids, a = [int(i) for i in j.get("ids", [])][:500], j.get("action")
    rows = q("SELECT id,s3_key,favorite FROM files WHERE user_id=%s AND id=ANY(%s)", (session["uid"], ids))
    if not rows: return {"ok": True}
    ids = [r["id"] for r in rows]
    if a == "trash": q("UPDATE files SET trashed_at=now(), share_slug=NULL WHERE id=ANY(%s)", (ids,))
    elif a == "restore": q("UPDATE files SET trashed_at=NULL WHERE id=ANY(%s)", (ids,))
    elif a == "fav": q("UPDATE files SET favorite=%s WHERE id=ANY(%s)", (not all(r["favorite"] for r in rows), ids))
    elif a == "purge": purge_rows(rows)
    else: abort(400)
    return {"ok": True}

@app.route("/api/rename/<int:fid>", methods=["POST"])
@login_required
def api_rename(fid):
    own(fid)
    n = os.path.basename(str((request.get_json(silent=True) or {}).get("name", "")).strip())[:200]
    if not n: return {"error": "Name required"}, 400
    q("UPDATE files SET name=%s WHERE id=%s", (n, fid)); return {"ok": True}

@app.errorhandler(413)
def too_big(e): return {"error": "File too large (max 4 MB without S3)."}, 413

@app.route("/api/presign", methods=["POST"])
@login_required
def api_presign():
    if not S3_ON: abort(404)
    j = request.get_json(silent=True) or {}
    name, mime, size = os.path.basename(str(j.get("name", "")))[:200], str(j.get("type") or "application/octet-stream")[:100], int(j.get("size") or 0)
    if not name or size <= 0: return {"error": "Invalid file."}, 400
    if used_bytes(session["uid"]) + size > CAP: return {"error": "Storage full."}, 400
    key = f"u{session['uid']}/{secrets.token_hex(8)}-{re.sub(r'[^A-Za-z0-9._-]', '_', name)}"
    r = q("INSERT INTO files(user_id,name,mime,kind,size,s3_key,ready) VALUES(%s,%s,%s,%s,%s,%s,FALSE) RETURNING id",
          (session["uid"], name, mime, kind_of(mime), size, key), one=True)
    return {"id": r["id"], "url": presign("put_object", key, 3600, ContentType=mime)}

@app.route("/api/done/<int:fid>", methods=["POST"])
@login_required
def api_done(fid):
    f = own(fid)
    try: head = s3().head_object(Bucket=os.environ["S3_BUCKET"], Key=f["s3_key"])
    except Exception: abort(400, "Upload missing")
    q("UPDATE files SET ready=TRUE,size=%s WHERE id=%s", (head["ContentLength"], fid)); return {"ok": True}

@app.route("/upload", methods=["POST"])  # fallback when S3 is not configured
@login_required
def upload():
    f = request.files.get("file")
    if S3_ON or not f: abort(400)
    data = f.read()
    mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
    if used_bytes(session["uid"]) + len(data) > CAP: return {"error": "Storage full."}, 400
    q("INSERT INTO files(user_id,name,mime,kind,size,data) VALUES(%s,%s,%s,%s,%s,%s)",
      (session["uid"], os.path.basename(f.filename)[:200], mime, kind_of(mime), len(data), psycopg2.Binary(data)))
    return {"ok": True}

@app.route("/f/<int:fid>")
@login_required
def serve(fid):
    own(fid); return send_row(fid, bool(request.args.get("dl")))

@app.route("/s/<slug>")
def shared(slug):
    f = q("SELECT id FROM files WHERE share_slug=%s AND ready AND trashed_at IS NULL AND (share_expires_at IS NULL OR share_expires_at>now())", (slug.lower(),), one=True)
    if not f: abort(404)
    q("UPDATE files SET share_views=share_views+1 WHERE id=%s", (f["id"],))
    return send_row(f["id"], bool(request.args.get("dl")))

def back(): return {"ok": True} if request.headers.get("X-CSRF") else redirect(request.referrer or url_for("home"))

@app.route("/share/<int:fid>", methods=["POST"])
@login_required
def share(fid):
    own(fid); d = int(request.form.get("days", 7))
    slug = secrets.token_urlsafe(6).lower().replace("_", "x").replace("-", "y")
    q("UPDATE files SET share_slug=%s, share_expires_at=CASE WHEN %s>0 THEN now()+%s*interval '1 day' END WHERE id=%s", (slug, d, d, fid))
    if request.headers.get("X-CSRF"): return {"url": f"{base_url()}/s/{slug}"}
    flash("Share link created."); return back()

@app.route("/unshare/<int:fid>", methods=["POST"])
@login_required
def unshare(fid):
    own(fid); q("UPDATE files SET share_slug=NULL, share_expires_at=NULL WHERE id=%s", (fid,)); return back()

@app.route("/fav/<int:fid>", methods=["POST"])
@login_required
def fav(fid):
    own(fid); q("UPDATE files SET favorite=NOT favorite WHERE id=%s", (fid,)); return back()

@app.route("/trash/<int:fid>", methods=["POST"])
@login_required
def trash(fid):
    own(fid); q("UPDATE files SET trashed_at=now(), share_slug=NULL WHERE id=%s", (fid,)); flash("Moved to Trash."); return back()

@app.route("/restore/<int:fid>", methods=["POST"])
@login_required
def restore(fid):
    own(fid); q("UPDATE files SET trashed_at=NULL WHERE id=%s", (fid,)); return back()

def purge_rows(rows):
    for r in rows:
        if r["s3_key"]:
            try: s3().delete_object(Bucket=os.environ["S3_BUCKET"], Key=r["s3_key"])
            except Exception: pass
        q("DELETE FROM files WHERE id=%s", (r["id"],))

@app.route("/purge/<int:fid>", methods=["POST"])
@login_required
def purge(fid):
    purge_rows([own(fid)]); flash("File deleted forever."); return back()

@app.route("/empty-trash", methods=["POST"])
@login_required
def empty_trash():
    purge_rows(q("SELECT id,s3_key FROM files WHERE user_id=%s AND trashed_at IS NOT NULL", (session["uid"],)))
    flash("Trash emptied."); return redirect(url_for("home", k="trash"))
