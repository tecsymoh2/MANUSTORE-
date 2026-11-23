from urllib.parse import parse_qsl, urlencode
import os, re, hmac, json, secrets, mimetypes, urllib.request, urllib.error
from datetime import timedelta
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

@app.route("/")
@login_required
def home():
    k, qs = request.args.get("k", "all"), request.args.get("s", "").strip()
    where, args = "user_id=%s AND ready", [session["uid"]]
    where += " AND trashed_at IS NOT NULL" if k == "trash" else " AND trashed_at IS NULL"
    if k == "fav": where += " AND favorite"
    if k in ("image", "video", "file"): where += " AND kind=%s"; args.append(k)
    if qs: where += " AND name ILIKE %s"; args.append(f"%{qs}%")
    rows = q(f"SELECT id,name,kind,size,favorite,share_slug,share_expires_at FROM files WHERE {where} ORDER BY created_at DESC", args)
    used = used_bytes(session["uid"])
    return page("""<h2>My files</h2>
<div class="card" style="max-width:none;margin:0 0 14px"><b>{{ hs(used) }}</b> <span class="mu">of {{ hs(cap) }} used</span>
<div class="bar"><i style="width:{{ [100, used*100/cap]|min }}%"></i></div>
<div class="up"><input type="file" id="pick" multiple><button class="btn" id="go" type="button">Upload</button><span class="mu" id="st">{{ 'Large files supported' if s3 else 'Max 4 MB per file (set up S3 for more)' }}</span></div></div>
<form class="up" method="get"><input type="hidden" name="k" value="{{k}}"><input type="text" name="s" value="{{qs}}" placeholder="Search files…" style="max-width:260px"></form>
<p class="tabs" style="margin-top:12px">{% for t,l in [('all','All'),('image','Images'),('video','Videos'),('file','Files'),('fav','★ Favorites'),('trash','🗑 Trash')] %}<a class="{{ 'on' if k==t }}" href="/?k={{t}}">{{l}}</a>{% endfor %}
{% if k=='trash' and rows %}<form method="post" action="/empty-trash" style="display:inline" onsubmit="return confirm('Delete everything in Trash forever?')">""" + CSRF + """<button class="btn sm red">Empty trash</button></form>{% endif %}</p>
{% if not rows %}<p class="mu">Nothing here yet.</p>{% endif %}
<div class="grid">{% for r in rows %}<div class="item"><a class="thumb" href="/f/{{r.id}}" target="_blank" style="text-decoration:none">
{% if r.kind=='image' %}<img loading="lazy" src="/f/{{r.id}}" alt="">{% elif r.kind=='video' %}🎬{% else %}📄{% endif %}</a>
<div class="meta"><b title="{{r.name}}">{{'★ ' if r.favorite}}{{r.name}}</b><span class="mu">{{ hs(r.size) }}</span>
{% if r.share_slug %}<input class="sl" readonly value="{{base}}/s/{{r.share_slug}}" onclick="this.select()">{% endif %}</div>
<div class="acts">{% if k=='trash' %}
<form method="post" action="/restore/{{r.id}}">""" + CSRF + """<button class="btn sm">Restore</button></form>
<form method="post" action="/purge/{{r.id}}" onsubmit="return confirm('Delete forever?')">""" + CSRF + """<button class="btn sm red">Delete</button></form>
{% else %}<form method="post" action="/fav/{{r.id}}">""" + CSRF + """<button class="btn sm gray">{{ '★' if r.favorite else '☆' }}</button></form>
{% if r.share_slug %}<form method="post" action="/unshare/{{r.id}}">""" + CSRF + """<button class="btn sm gray">Unshare</button></form>
{% else %}<form method="post" action="/share/{{r.id}}">""" + CSRF + """<select name="days" style="font-size:.8rem"><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option><option value="0">No expiry</option></select><button class="btn sm gray">Share</button></form>{% endif %}
<a class="btn sm" href="/f/{{r.id}}?dl=1">⬇</a>
<form method="post" action="/trash/{{r.id}}">""" + CSRF + """<button class="btn sm red">🗑</button></form>{% endif %}</div></div>{% endfor %}</div>
<script>const CSRF="{{ session.csrf }}",S3={{ s3|tojson }};</script>
{% raw %}<script>
const st=document.getElementById('st');
function xhr(method,url,body,type,label){return new Promise((ok,no)=>{const x=new XMLHttpRequest();x.open(method,url);
 if(type)x.setRequestHeader('Content-Type',type);x.setRequestHeader('X-CSRF',CSRF);
 x.upload.onprogress=e=>{if(e.lengthComputable)st.textContent=label+' '+Math.round(e.loaded*100/e.total)+'%'};
 x.onload=()=>x.status<300?ok(x.responseText):no(new Error((()=>{try{return JSON.parse(x.responseText).error}catch(e){return 'Upload failed'}})()));
 x.onerror=()=>no(new Error('Network error — check bucket CORS'));x.send(body)})}
async function up(f){const type=f.type||'application/octet-stream',label=f.name;
 if(S3){const r=await fetch('/api/presign',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({name:f.name,type:type,size:f.size})});
  const j=await r.json();if(!r.ok)throw new Error(j.error);
  await xhr('PUT',j.url,f,type,label);
  const d=await fetch('/api/done/'+j.id,{method:'POST',headers:{'X-CSRF':CSRF}});if(!d.ok)throw new Error('Could not finish upload');
 }else{const fd=new FormData();fd.append('file',f);await xhr('POST','/upload',fd,null,label)}}
document.getElementById('go').onclick=async()=>{const fs=[...document.getElementById('pick').files];if(!fs.length)return;
 try{for(const f of fs)await up(f);location.reload()}catch(e){st.textContent='⚠ '+e.message}};
</script>{% endraw %}""", "My files", rows=rows, k=k, qs=qs, used=used, cap=CAP, hs=human, s3=S3_ON, base=base_url())

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

def back(): return redirect(request.referrer or url_for("home"))

@app.route("/share/<int:fid>", methods=["POST"])
@login_required
def share(fid):
    own(fid); d = int(request.form.get("days", 7))
    q("UPDATE files SET share_slug=%s, share_expires_at=CASE WHEN %s>0 THEN now()+%s*interval '1 day' END WHERE id=%s",
      (secrets.token_urlsafe(6).lower().replace("_", "x").replace("-", "y"), d, d, fid))
    flash("Share link created — copy it from the file card."); return back()

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
