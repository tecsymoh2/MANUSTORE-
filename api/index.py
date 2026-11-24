from urllib.parse import parse_qsl, urlencode, urlparse
import os, re, time, hmac, json, hashlib, smtplib, ssl, urllib.parse, secrets, mimetypes, urllib.request, urllib.error
from datetime import timedelta, datetime, timezone
from functools import wraps
import psycopg2, psycopg2.extras
from markupsafe import escape
from email.message import EmailMessage
from flask import (g, Flask, request, session, redirect, url_for, flash,
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

ADMIN_EMAILS = {e.strip().lower() for e in os.environ.get("ADMIN_EMAILS", "").split(",") if e.strip()}
GB = 2 ** 30

def user():
    if "u" not in g:
        g.u = q("SELECT id,username,email,quota_bytes,is_admin,blocked FROM users WHERE id=%s", (session["uid"],), one=True) if session.get("uid") else None
    return g.u

def is_admin(u): return bool(u and (u["is_admin"] or u["email"] in ADMIN_EMAILS))

def login_required(f):
    @wraps(f)
    def w(*a, **k):
        u = user()
        if not u or u["blocked"]: session.clear(); return redirect(url_for("login"))
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        u = user()
        if not u or u["blocked"]: session.clear(); return redirect(url_for("login"))
        if not is_admin(u): abort(404)
        return f(*a, **k)
    return w

def csrf_ok():
    """Token match, or (when the token is stale/missing) a same-origin request. Cross-site posts are still rejected."""
    tok = request.form.get("csrf") or request.headers.get("X-CSRF", "")
    if tok and hmac.compare_digest(tok, session.get("csrf", "")): return True
    src = request.headers.get("Origin") or request.headers.get("Referer", "")
    return bool(src) and urlparse(src).netloc == request.host

@app.before_request
def guard():
    session.setdefault("csrf", secrets.token_hex(16))
    if request.method == "POST" and request.path not in ("/api/pay/webhook", "/logout") and not csrf_ok():
        if request.headers.get("X-CSRF") is not None or request.is_json:
            return {"error": "Your session expired. Please refresh the page."}, 400
        flash("Your session expired — please try again.", "error")
        return redirect(url_for("home" if session.get("uid") else "login"))

@app.after_request
def no_cache(r):
    if r.mimetype == "text/html": r.headers["Cache-Control"] = "no-store"
    return r

def kind_of(mime):
    return "image" if mime.startswith("image/") else "video" if mime.startswith("video/") else "file"

# ---------- templates ----------
STYLE = r"""  :root{
    --paper:#c7a97b;
    --paper-deep:#b6944e;
    --tag:#ecdfba;
    --ink:#221b12;
    --crate:#5a3a22;
    --crate-dark:#402a18;
    --stamp:#b7381f;
    --teal:#2e5c55;
    --line: rgba(34,27,18,0.28);
    --shadow: 0 10px 24px rgba(34,27,18,0.28);
    --surface:#fbf6e9;
  }
  html[data-theme="dark"]{
    --paper:#211c16;
    --paper-deep:#171310;
    --tag:#2b241b;
    --ink:#ecdfba;
    --crate:#3a2f22;
    --crate-dark:#171310;
    --stamp:#e05a3f;
    --teal:#5fb3a4;
    --line: rgba(236,223,186,0.2);
    --shadow: 0 10px 24px rgba(0,0,0,0.5);
    --surface:#181410;
  }
  *{box-sizing:border-box;}
  html,body{margin:0;padding:0;}
  body{
    font-family:'Work Sans', sans-serif;
    color:var(--ink);
    background:
      repeating-linear-gradient(135deg, rgba(0,0,0,0.02) 0 2px, transparent 2px 6px),
      var(--paper);
    min-height:100vh;
    transition:background .2s ease, color .2s ease;
  }
  h1,h2,h3,.display{
    font-family:'Oswald', sans-serif;
    text-transform:uppercase;
    letter-spacing:0.04em;
    margin:0;
  }
  .mono{font-family:'JetBrains Mono', monospace;}
  button, input, textarea, select{font-family:inherit; font-size:inherit;}
  button{cursor:pointer;}
  a{color:var(--teal);}

  /* ---------- layout shells ---------- */
  .screen{min-height:100vh; display:flex; align-items:center; justify-content:center; padding:24px;}
  .hidden{display:none !important;}

  /* ---------- login ---------- */
  .gate-card{
    width:100%; max-width:380px;
    background:var(--tag);
    border:2px solid var(--ink);
    border-radius:4px;
    padding:32px 28px 28px;
    box-shadow:var(--shadow);
    position:relative;
  }
  .gate-card::before{
    content:"";
    position:absolute; top:-10px; left:20px; right:20px; height:20px;
    background-image: radial-gradient(circle, var(--paper) 5px, transparent 5.5px);
    background-size: 20px 20px;
    background-position: 0 0;
  }
  .gate-mark{
    width:56px;height:56px;margin:0 auto 14px;
    border:2px solid var(--ink); border-radius:50%;
    display:flex; align-items:center; justify-content:center;
  }
  .gate-title{text-align:center; font-size:26px;}
  .gate-sub{text-align:center; font-size:12px; letter-spacing:0.18em; text-transform:uppercase; color:var(--crate-dark); margin-top:4px; margin-bottom:22px;}
  .field{margin-bottom:16px;}
  .field label{display:block; font-size:11px; letter-spacing:0.12em; text-transform:uppercase; color:var(--crate-dark); margin-bottom:6px;}
  .field input, .field select{
    width:100%; padding:11px 12px; border:1.5px solid var(--ink); border-radius:3px;
    background:var(--surface); color:var(--ink);
  }
  .field input:focus, .field select:focus{outline:2px solid var(--teal); outline-offset:1px;}
  .btn{
    display:inline-flex; align-items:center; justify-content:center; gap:8px;
    border:2px solid var(--ink); border-radius:3px; padding:11px 18px;
    background:var(--ink); color:var(--tag);
    font-family:'Oswald',sans-serif; text-transform:uppercase; letter-spacing:0.08em; font-size:13px;
    transition:transform .12s ease;
  }
  .btn:active{transform:scale(0.97);}
  .btn:disabled{opacity:0.6; cursor:default;}
  .btn.block{width:100%;}
  .btn.stamp{background:var(--stamp); border-color:var(--stamp); color:#fbf6e9;}
  .btn.ghost{background:transparent; color:var(--ink);}
  .btn.teal{background:var(--teal); border-color:var(--teal); color:#fbf6e9;}
  .btn.sm{padding:6px 10px; font-size:11px;}
  .err{color:var(--stamp); font-size:12.5px; margin-top:10px; text-align:center;}
  .hint{font-size:11px; color:var(--crate-dark); text-align:center; margin-top:16px; line-height:1.5;}

  /* ---------- app shell ---------- */
  .app{max-width:1080px; margin:0 auto; padding:18px 16px 60px;}
  .topbar{
    display:flex; align-items:center; gap:12px; flex-wrap:wrap;
    background:var(--crate); color:var(--tag);
    border:2px solid var(--ink); border-radius:4px;
    padding:14px 16px; margin-bottom:12px; box-shadow:var(--shadow);
  }
  .brand{font-size:20px; white-space:nowrap;}
  .brand span{color:var(--stamp);}
  .search-wrap{flex:1; min-width:160px; display:flex; align-items:center; gap:8px; background:var(--surface); border:1.5px solid var(--ink); border-radius:3px; padding:8px 10px;}
  .search-wrap input{flex:1; border:none; background:transparent; color:var(--ink);}
  .search-wrap input:focus{outline:none;}
  .topbar .btn{padding:9px 14px; font-size:12px;}
  .icon-btn{
    border:1.5px solid var(--tag); background:transparent; color:var(--tag);
    border-radius:3px; padding:8px 10px; font-size:14px;
  }

  .stats-bar{
    display:flex; gap:16px; flex-wrap:wrap; font-size:11.5px; color:var(--crate-dark);
    margin-bottom:18px; padding:0 4px;
  }
  .stats-bar b{color:var(--ink);}

  .offline-banner{
    background:var(--stamp); color:#fff; border-radius:4px; padding:10px 14px;
    font-size:12.5px; margin-bottom:16px; text-align:center;
  }

  .trash-row{
    display:flex; align-items:center; gap:10px; background:var(--surface);
    border:1px solid var(--line); border-radius:4px; padding:8px 10px; font-size:12px;
  }
  .trash-row .trash-info{flex:1; min-width:0;}
  .trash-row .trash-desc{white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
  .trash-row .trash-meta{color:var(--crate-dark); font-size:10.5px;}
  .trash-row .btn{padding:6px 9px; font-size:10px;}

  .filter-bar{display:flex; align-items:center; gap:10px; flex-wrap:wrap; margin-bottom:20px;}
  .pill-group{display:flex; gap:6px; flex-wrap:wrap;}
  .pill{
    padding:6px 12px; border:1.5px solid var(--ink); border-radius:20px; background:transparent; color:var(--ink);
    font-family:'Oswald',sans-serif; letter-spacing:0.05em; text-transform:uppercase; font-size:11px;
  }
  .pill.active{background:var(--ink); color:var(--tag);}
  .filter-bar select{
    border:1.5px solid var(--ink); border-radius:3px; padding:7px 10px; background:var(--surface); color:var(--ink); font-size:12px;
  }

  .section-title{font-size:14px; letter-spacing:0.14em; color:var(--crate-dark); margin-bottom:12px; display:flex; align-items:center; gap:10px;}
  .section-title::after{content:""; flex:1; height:1px; background:var(--line);}

  /* ---------- intake form ---------- */
  .intake{
    background:var(--tag); border:2px solid var(--ink); border-radius:4px;
    padding:20px; margin-bottom:30px; box-shadow:var(--shadow);
  }
  .tabs{display:flex; gap:8px; margin-bottom:16px; flex-wrap:wrap;}
  .tab-btn{
    padding:8px 14px; border:1.5px solid var(--ink); border-radius:20px; background:transparent; color:var(--ink);
    font-family:'Oswald',sans-serif; letter-spacing:0.06em; text-transform:uppercase; font-size:12px;
  }
  .tab-btn.active{background:var(--ink); color:var(--tag);}
  .src-toggle{display:flex; gap:8px; margin-bottom:14px;}
  .src-btn{
    flex:1; padding:9px; border:1.5px dashed var(--ink); border-radius:3px; background:var(--surface); color:var(--ink);
    font-size:12.5px; text-align:center;
  }
  .src-btn.active{background:var(--ink); color:var(--tag); border-style:solid;}
  .field textarea{
    width:100%; padding:11px 12px; border:1.5px solid var(--ink); border-radius:3px;
    background:var(--surface); color:var(--ink); resize:vertical; min-height:70px;
  }
  .dropzone{
    border:2px dashed var(--ink); border-radius:4px; padding:22px 12px; text-align:center;
    background:var(--surface); cursor:pointer; font-size:12.5px; color:var(--crate-dark);
  }
  .dropzone.drag-over{background:var(--tag); border-color:var(--teal); color:var(--teal);}
  .dropzone input{display:none;}
  .file-list{display:flex; flex-direction:column; gap:4px; margin-top:8px; font-size:11.5px;}
  .file-list span{display:flex; justify-content:space-between; background:var(--surface); padding:4px 8px; border-radius:3px;}
  .two-col{display:grid; grid-template-columns:1fr 1fr; gap:12px;}
  .intake-actions{display:flex; justify-content:flex-end; gap:10px; margin-top:6px;}
  .progress{font-size:12px; color:var(--crate-dark); margin-top:8px;}

  /* ---------- grid ---------- */
  .grid{display:grid; grid-template-columns:repeat(auto-fill,minmax(230px,1fr)); gap:18px;}
  .card{
    background:var(--tag); border:2px solid var(--ink); border-radius:4px; overflow:hidden;
    box-shadow:var(--shadow); display:flex; flex-direction:column; position:relative;
  }
  .card-media{height:150px; background:var(--crate-dark); display:flex; align-items:center; justify-content:center; overflow:hidden;}
  .card-media img, .card-media video{width:100%; height:100%; object-fit:cover;}
  .card-media .icon{color:var(--tag); font-size:34px;}
  .stamp-tag{
    position:absolute; top:10px; right:10px; transform:rotate(6deg);
    border:2px solid var(--stamp); color:var(--stamp); border-radius:4px;
    padding:2px 8px; font-family:'Oswald',sans-serif; font-size:10px; letter-spacing:0.1em;
    background:rgba(251,246,233,0.85);
  }
  .expired-tag{
    position:absolute; top:10px; left:10px;
    background:var(--stamp); color:#fff; border-radius:4px; padding:2px 8px;
    font-family:'Oswald',sans-serif; font-size:9.5px; letter-spacing:0.1em;
  }
  .select-check{position:absolute; top:10px; left:10px; width:20px; height:20px; z-index:2;}
  .card-body{padding:12px 14px 14px; display:flex; flex-direction:column; gap:8px; flex:1;}
  .card-desc{font-size:13.5px; line-height:1.4; flex:1; word-break:break-word;}
  .tag-pills{display:flex; flex-wrap:wrap; gap:4px;}
  .tag-pill{font-size:9.5px; padding:2px 7px; border-radius:10px; background:var(--surface); border:1px solid var(--line); color:var(--crate-dark);}
  .card-meta{font-size:10.5px; color:var(--crate-dark); display:flex; justify-content:space-between; border-top:1px dashed var(--line); padding-top:8px;}
  .card-actions{display:flex; gap:6px; flex-wrap:wrap;}
  .card-actions .btn{flex:1; padding:7px 8px; font-size:10.5px; min-width:60px;}
  .empty{
    text-align:center; padding:50px 20px; color:var(--crate-dark);
    border:2px dashed var(--line); border-radius:4px;
  }

  /* ---------- modal ---------- */
  .modal-back{position:fixed; inset:0; background:rgba(34,27,18,0.55); display:flex; align-items:center; justify-content:center; padding:20px; z-index:50;}
  .modal{
    background:var(--tag); border:2px solid var(--ink); border-radius:4px; max-width:420px; width:100%;
    padding:24px; box-shadow:var(--shadow); text-align:center; max-height:90vh; overflow:auto;
  }
  .modal .code{
    font-size:22px; letter-spacing:0.08em; background:var(--ink); color:var(--tag);
    padding:10px; border-radius:3px; margin:14px 0; word-break:break-all;
  }
  .modal .qr{margin:14px auto; border:2px solid var(--ink); border-radius:4px; display:block;}
  .link-row{display:flex; flex-direction:column; gap:10px; margin:16px 0;}
  .link-row .btn{width:100%;}
  .copied{font-size:11px; color:var(--teal); margin-top:4px; height:14px;}

  /* ---------- public view page ---------- */
  .pub-wrap{max-width:520px; margin:0 auto; padding:40px 18px;}
  .pub-card{
    background:var(--tag); border:2px solid var(--ink); border-radius:4px; overflow:hidden; box-shadow:var(--shadow);
  }
  .pub-media{width:100%; max-height:460px; background:var(--crate-dark); display:flex; align-items:center; justify-content:center;}
  .pub-media img, .pub-media video{width:100%; max-height:460px; object-fit:contain;}
  .pub-body{padding:20px;}
  .pub-foot{text-align:center; margin-top:18px; font-size:12px; color:var(--crate-dark);}

  /* ---------- toast ---------- */
  .toast{
    position:fixed; bottom:20px; left:50%; transform:translateX(-50%);
    background:var(--ink); color:var(--tag); border-radius:4px; padding:12px 16px;
    display:flex; align-items:center; gap:14px; font-size:13px; box-shadow:var(--shadow); z-index:60;
  }
  .toast button{background:none; border:none; color:var(--stamp); font-family:'Oswald',sans-serif; text-transform:uppercase; letter-spacing:0.06em; font-size:12px;}

  /* ---------- bulk bar ---------- */
  .bulk-bar{
    display:none; align-items:center; justify-content:space-between; gap:10px;
    background:var(--stamp); color:#fff; border-radius:4px; padding:10px 14px; margin-bottom:16px;
    font-size:12.5px;
  }
  .bulk-bar.show{display:flex;}

  @media (max-width:480px){
    .brand{font-size:17px;}
    .modal{padding:18px;}
    .two-col{grid-template-columns:1fr;}
  }
/* shims so existing auth markup uses the Symoh Store look */
.gate-card h2{text-align:center;font-size:20px;margin:0 0 10px}.gate-card label{display:block;font-size:11px;letter-spacing:.12em;text-transform:uppercase;color:var(--crate-dark);margin:14px 0 6px}
.gate-card input[type=text],.gate-card input[type=email],.gate-card input[type=password],.gate-card input[type=number]{width:100%;padding:11px 12px;border:1.5px solid var(--ink);border-radius:3px;background:var(--surface);color:var(--ink)}
.btn.full{width:100%;margin-top:16px;background:var(--stamp);border-color:var(--stamp);color:#fbf6e9}.btn.gray{background:transparent;color:var(--ink)}.mu{color:var(--crate-dark);font-size:12px;text-align:center;margin:12px 0 0}
.pw{position:relative}.pw button{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:0;color:var(--teal);font-size:12px;text-transform:uppercase}
.flash{background:var(--teal);color:#fff;border-radius:4px;padding:9px 12px;font-size:12.5px;margin-bottom:12px;text-align:center}.flash.error{background:var(--stamp)}
.wrapg{width:100%;max-width:380px}.sm-only{display:none}
input[type=text],input[type=url],textarea,select{color:var(--ink)}.app input[type=text],.app input[type=url],.app textarea,.pub-card input,.pub-card textarea{width:100%;padding:10px 12px;border:1.5px solid var(--ink);border-radius:3px;background:var(--surface);color:var(--ink)}
.app input[type=checkbox]{width:auto}.search-wrap{margin:0}.search-wrap input{border:0!important;padding:0!important;background:transparent!important}
.fv{position:absolute;bottom:8px;right:8px;background:var(--tag);border:1.5px solid var(--ink);border-radius:3px;padding:2px 8px;color:var(--ink)}
.card-media{cursor:pointer;position:relative}.card.sel{outline:3px solid var(--teal);outline-offset:-3px}
.qrow{display:flex;gap:8px;align-items:center;background:var(--surface);border:1px solid var(--line);border-radius:3px;padding:6px}.qt{width:44px;height:44px;flex:none;border-radius:3px;overflow:hidden;background:var(--crate-dark);display:grid;place-items:center;color:var(--tag)}.qt img,.qt video{width:100%;height:100%;object-fit:cover}
.qm{flex:1;min-width:0}.qn{display:flex;gap:4px;align-items:center}.qn input{padding:5px 8px!important;font-size:12px}.ss{font-size:11px;color:var(--crate-dark)}.pb{height:4px;background:var(--line);border-radius:2px;margin-top:4px}.pb i{display:block;height:100%;width:0;background:var(--teal)}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0;justify-content:center}.cw{position:relative;display:inline-block;touch-action:none;max-width:100%}#ec{max-width:100%;max-height:42vh;display:block;border:2px solid var(--ink);background:#000}
#cr{position:absolute;border:2px solid #fff;box-shadow:0 0 0 9999px #0008;display:none;pointer-events:none}.row label{font-size:11px;text-transform:uppercase;letter-spacing:.08em}
.cm-i{background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:8px 10px;font-size:13px;text-align:left}.hb2{display:flex;justify-content:space-between;gap:6px;font-size:10.5px;color:var(--crate-dark)}
.plan{display:flex;gap:10px;align-items:center;justify-content:space-between;border:2px solid var(--ink);border-radius:4px;padding:12px;background:var(--surface);cursor:pointer}.plan input[type=radio]{width:auto}.plan span:first-of-type{flex:1}
.tw{overflow-x:auto}.at{width:100%;border-collapse:collapse;font-size:12.5px;background:var(--tag);border:2px solid var(--ink)}.at th,.at td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}.at th{font-size:11px;letter-spacing:.1em;text-transform:uppercase}
.app textarea{font-family:inherit}
.fullbox{position:relative;display:flex;align-items:center;gap:16px;flex-wrap:wrap;background:var(--stamp);color:#fff;border:3px solid var(--ink);border-radius:6px;padding:18px 20px 26px;margin:14px 0;box-shadow:var(--shadow);overflow:hidden}
.fullbox:before{content:"";position:absolute;left:0;right:0;bottom:0;height:8px;background:repeating-linear-gradient(45deg,var(--ink) 0 10px,#e8b923 10px 20px)}.fullbox.warn{background:#b6791f}
.fb-i{font-size:46px;animation:pul 1.6s infinite}@keyframes pul{50%{transform:scale(1.14)}}.fb-t{font-size:34px;letter-spacing:.08em;line-height:1;margin-bottom:6px}.fb-s{font-size:14px;line-height:1.45;max-width:540px}
.fb-a{display:flex;gap:8px;flex-wrap:wrap;margin-left:auto}.fb-a .btn{background:#fbf6e9;color:var(--ink);border-color:var(--ink);text-decoration:none}.fb-a .btn.hot{background:var(--ink);color:#fbf6e9}
.pl-hero{border:3px solid var(--ink);border-radius:6px;padding:22px 18px;margin:16px 0;background:var(--tag);box-shadow:var(--shadow);text-align:center}.pl-hero.full{background:var(--stamp);color:#fff}.pl-hero.warn{background:#b6791f;color:#fff}
.pl-h{font-size:38px;letter-spacing:.08em}.pl-meter{height:16px;border:2px solid var(--ink);border-radius:8px;background:#0003;overflow:hidden;margin:14px auto 6px;max-width:520px}.pl-meter i{display:block;height:100%;background:var(--teal)}.pl-hero.full .pl-meter i,.pl-hero.warn .pl-meter i{background:#fbf6e9}
.pl-m2{display:flex;justify-content:space-between;max-width:520px;margin:0 auto;font-size:12px}
.pl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(235px,1fr));gap:18px;margin-top:14px}.pl-card{position:relative;background:var(--tag);border:2px solid var(--ink);border-radius:6px;padding:20px 18px;box-shadow:var(--shadow);text-align:center;display:flex;flex-direction:column;gap:8px}
.pl-card.sel{outline:4px solid var(--teal);outline-offset:3px}.pl-ribbon{position:absolute;top:-12px;right:12px;background:var(--teal);color:#fff;font-size:11px;letter-spacing:.1em;text-transform:uppercase;padding:4px 10px;border-radius:3px;border:2px solid var(--ink)}
.pl-gb{font-size:46px;line-height:1.1}.pl-gb small{font-size:18px}.pl-price{font-size:22px;font-weight:600}.pl-per{font-size:12px;color:var(--crate-dark)}.pl-d{font-size:13px;margin:4px 0}.pl-tip{font-size:12px;color:var(--teal);min-height:16px}
.pl-ul{list-style:none;padding:0;margin:0 0 8px;font-size:13px;text-align:left}.pl-ul li:before{content:"✓ ";color:var(--teal);font-weight:700}.pl-card .btn{margin-top:auto}
.pl-f{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin-top:12px}.pl-f>div{background:var(--tag);border:1.5px solid var(--ink);border-radius:4px;padding:12px;font-size:13px}.pl-f b{display:block;margin-bottom:3px}
.pl-q{background:var(--tag);border:1.5px solid var(--ink);border-radius:4px;padding:10px 14px;margin-top:8px}.pl-q summary{cursor:pointer;font-weight:600}.pl-q p{font-size:13px;margin:8px 0 2px}
"""

LAYOUT = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#5a3a22">
<title>{{ title or 'YIM CLOUD STORAGE' }}</title>{{ head|safe }}
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Oswald:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&family=Work+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<style>{{ css|safe }}</style>
<script>try{var t=localStorage.getItem('theme');if(t)document.documentElement.dataset.theme=t}catch(e){}</script></head><body>
{% if full %}{{ body|safe }}{% else %}<div class="screen"><div class="wrapg"><div class="gate-card"><div class="gate-mark">☁️</div>
<div class="gate-title display">YIM <span style="color:var(--stamp)">CLOUD STORAGE</span></div><div class="gate-sub">Checkpoint · handlers only</div>
{% for c,m in get_flashed_messages(with_categories=true) %}<div class="flash {{c}}">{{m}}</div>{% endfor %}
{{ body|safe }}</div><div class="pub-foot">DEVELOPED BY SYMOH TECH</div></div></div>{% endif %}
<script>document.querySelectorAll('.pw button').forEach(b=>b.onclick=()=>{const i=b.parentNode.querySelector('input');const s=i.type==='password';i.type=s?'text':'password';b.textContent=s?'Hide':'Show'})</script>
</body></html>"""

def page(body, title=None, full=False, head="", **ctx):
    inner = render_template_string(body, **ctx)
    return render_template_string(LAYOUT, body=inner, title=title, full=full, head=head, css=STYLE)

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
                q("INSERT INTO users(username,email,auth_id,verified,welcomed,quota_bytes) VALUES(%s,%s,%s,FALSE,FALSE,%s) ON CONFLICT DO NOTHING",
                  (u, e, (d.get("user") or {}).get("id"), int(float(settings_all()["free_gb"]) * GB)))
                log_act(None, "signup", e)
                flash("Account created! We emailed you a verification code.")
                return redirect(url_for("verify", email=e))
    return page("""<div><h2>Create account</h2><form method="post">""" + CSRF + """
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
                welcome(email)
                flash("Email verified! You can log in now."); return redirect(url_for("login"))
            flash(emsg(d), "error")
    return page("""<div><h2>Verify your email</h2><p class="mu">Enter the code we emailed you.</p><form method="post">""" + CSRF + """
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
            else:
                if u.get("blocked"): flash("This account has been suspended.", "error"); return redirect(url_for("login"))
                welcome(email)
            session.clear(); session.permanent = True
            session.update(uid=u["id"], uname=u["username"], csrf=secrets.token_hex(16))
            return redirect(url_for("home"))
        if code == 403 or d.get("code") == "EMAIL_NOT_VERIFIED":
            neon_auth("/email-otp/send-verification-otp", {"email": email, "type": "email-verification"})
            flash("Please verify your email — we sent you a new code."); return redirect(url_for("verify", email=email))
        flash("Wrong username/email or password." if code in (400, 401) else emsg(d), "error")
    return page("""<div><h2>Welcome back</h2><form method="post">""" + CSRF + """
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
    return page("""<div><h2>Forgot password</h2><form method="post">""" + CSRF + """
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
    return page("""<div><h2>Reset password</h2><form method="post">""" + CSRF + """
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

DASH = r"""<div class="app">
<div class="topbar"><div class="brand display">YIM <span>CLOUD STORAGE</span></div>
<form class="search-wrap" method="get"><span>🔍</span><input name="s" value="{{qs}}" placeholder="Search the manifest…"><input type="hidden" name="k" value="{{k}}"><input type="hidden" name="o" value="{{o}}"></form>
<button class="btn teal" id="newb">＋ New Parcel</button><button class="btn ghost" id="selb">Select</button>
<div style="position:relative"><button class="icon-btn" id="mmb">⋯ More</button>
<div id="mm" class="hidden" style="position:absolute;right:0;top:calc(100% + 6px);background:var(--tag);border:2px solid var(--ink);border-radius:4px;box-shadow:var(--shadow);z-index:40;min-width:210px;flex-direction:column;display:flex">
<button class="btn ghost" id="themeb" style="justify-content:flex-start">🌙 Dark mode</button>
<a class="btn ghost" href="/?k=fav" style="justify-content:flex-start;text-decoration:none">★ Favorites</a>
<a class="btn ghost" href="/?k=trash" style="justify-content:flex-start;text-decoration:none">🗑 Trash</a>
<a class="btn ghost" href="/plans" style="justify-content:flex-start;text-decoration:none">💳 Storage &amp; plans</a>
{% if admin %}<a class="btn ghost" href="/admin" style="justify-content:flex-start;text-decoration:none">⚙ Admin</a>{% endif %}
{% if k=='trash' and items %}<button class="btn ghost" id="emptyb" style="justify-content:flex-start">⚠ Empty trash</button>{% endif %}</div></div>
<form method="post" action="/logout"><input type="hidden" name="csrf" value="{{ session.csrf }}"><button class="btn ghost">Sign out</button></form></div>
{% if used>=cap %}<div class="fullbox"><div class="fb-i">🚫</div><div><div class="fb-t display">Storage full</div>
<div class="fb-s">You've used <b>{{ hs(used) }}</b> of <b>{{ hs(cap) }}</b>. <b>New uploads are paused</b> until you free up space or add more storage.</div></div>
<div class="fb-a"><a class="btn hot" href="/plans">See plans →</a><a class="btn" href="/?k=trash">Free up space</a></div></div>
{% elif used*100/cap>=90 %}<div class="fullbox warn"><div class="fb-i">⚠️</div><div><div class="fb-t display">Almost full</div>
<div class="fb-s">You've used <b>{{ (used*100/cap)|round|int }}%</b> ({{ hs(used) }} of {{ hs(cap) }}). Top up before you run out.</div></div>
<div class="fb-a"><a class="btn hot" href="/plans">See plans →</a></div></div>{% endif %}
{% for c,m in fl %}<div class="offline-banner" style="{{ '' if c=='error' else 'background:var(--teal)' }}">{{m}}</div>{% endfor %}
<div class="stats-bar"><span><b>{{ items|length }}</b> parcels loaded</span><span><b>{{ hs(used) }}</b> of {{ hs(cap) }} used</span><span>last shipped <b>{{ last }}</b></span></div>
<div class="bulk-bar" id="bulkbar"><span id="bc">0 selected</span><div style="display:flex;gap:6px;flex-wrap:wrap">
{% if k=='trash' %}<button class="btn ghost sm" style="color:#fff;border-color:#fff" onclick="bulk('restore')">Restore</button><button class="btn stamp sm" style="border-color:#fff" onclick="confirm('Delete forever?')&&bulk('purge')">Delete forever</button>
{% else %}<button class="btn ghost sm" style="color:#fff;border-color:#fff" onclick="bulkTag()">＋ Tag</button><button class="btn ghost sm" style="color:#fff;border-color:#fff" onclick="bulk('fav')">★ Favorite</button><button class="btn stamp sm" style="border-color:#fff" onclick="bulk('trash')">Delete</button>{% endif %}</div></div>
<div class="filter-bar"><div class="pill-group">{% for t,l in [('all','All'),('image','Image'),('video','Video'),('file','File')] %}<a class="pill {{ 'active' if k==t }}" href="/?k={{t}}&o={{o}}" style="text-decoration:none">{{l}}</a>{% endfor %}</div>
<form method="get" style="margin:0"><input type="hidden" name="k" value="{{k}}"><input type="hidden" name="s" value="{{qs}}"><select name="o" onchange="this.form.submit()">{% for v,l in [('new','Newest first'),('old','Oldest first'),('big','Largest first'),('name','Name A–Z')] %}<option value="{{v}}" {{ 'selected' if o==v }}>{{l}}</option>{% endfor %}</select></form></div>

<div class="intake hidden" id="intake"><div class="section-title">Intake a new parcel</div>
<div class="tabs"><button type="button" class="tab-btn active" data-t="">All</button><button type="button" class="tab-btn" data-t="image/*">Image</button><button type="button" class="tab-btn" data-t="video/*">Video</button><button type="button" class="tab-btn" data-t="*/*">File</button></div>
<div class="field"><label>Choose file(s) — or drag &amp; drop</label><div class="dropzone" id="dz"><div>Tap to choose files, or drop them here</div><input type="file" id="pick" multiple></div>
<div class="file-list" id="ql" style="gap:6px"></div>
<label style="display:flex;align-items:center;gap:8px;margin-top:8px;text-transform:none;letter-spacing:normal;font-size:12px">Auto-shrink before upload:
<select id="qs" style="padding:6px"><option value="o">Original (no shrink)</option><option value="h">High (2560px / 1080p)</option><option value="m" selected>Medium (1920px / 720p)</option><option value="l">Low (1280px / 480p)</option></select></label>
<div class="hint" style="text-align:left;margin-top:6px">Videos are re-encoded in your browser — keep this tab open while they shrink.</div></div>
<div class="field"><label>Description</label><textarea id="desc" placeholder="What's in this parcel? (applies to all files if uploading several)"></textarea></div>
<div class="field"><label>Tags</label><input type="text" id="tags" placeholder="comma, separated, tags"></div>
<div class="intake-actions"><button type="button" class="btn ghost" id="cancelb">Cancel</button><button type="button" class="btn stamp" id="ug">Ship it</button></div><div class="progress" id="us"></div></div>

<div class="section-title">{{ 'Trash' if k=='trash' else 'Manifest' }}</div>
{% if not items %}<div class="empty">{{ 'Nothing here yet.' if k!='all' or qs else 'No parcels yet — hit NEW PARCEL to ship your first.' }}</div>{% endif %}
<div id="grid" class="grid">{% for r in rows %}<div class="card" data-i="{{r.i}}" data-id="{{r.id}}">
<div class="card-media" data-a="pv">{% if r.kind=='image' %}<img loading="lazy" decoding="async" src="/f/{{r.id}}" alt="">{% elif r.kind=='video' %}<video muted preload="metadata" src="/f/{{r.id}}#t=0.1"></video>{% else %}<span class="icon">📄</span>{% endif %}
{% if k!='trash' %}<button class="fv" data-a="fv">{{ '★' if r.favorite else '☆' }}</button>{% endif %}</div>
<div class="stamp-tag">{{ r.kind|upper }}</div><input type="checkbox" class="select-check hidden" tabindex="-1">
<div class="card-body"><div class="card-desc">{{ r.description or '(no description)' }}</div>
{% if r.tagl %}<div class="tag-pills">{% for t in r.tagl %}<span class="tag-pill">{{t}}</span>{% endfor %}</div>{% endif %}
<div class="card-meta"><span class="mono">#{{r.sid}}</span><span>{{r.dt}}</span></div>
<div class="card-meta" style="border:0;padding:0"><span>👁 {{r.share_views}} views</span><span>{{r.lv}}</span></div>
<div class="card-actions"><button class="btn ghost" data-a="pv">Preview</button>{% if k=='trash' %}<button class="btn teal" data-a="rs">Restore</button>{% else %}<button class="btn teal" data-a="sh">Share</button>{% endif %}<a class="btn ghost" href="/f/{{r.id}}?dl=1" style="text-decoration:none">↓ Download</a></div>
<div class="card-actions">{% if k!='trash' %}<button class="btn ghost" data-a="ed">Edit</button><button class="btn ghost" data-a="cm">💬</button>{% endif %}<button class="btn stamp" data-a="rm">{{ 'Delete forever' if k=='trash' else 'Delete' }}</button></div></div></div>{% endfor %}</div>
<div class="pub-foot" style="margin-top:30px">DEVELOPED BY SYMOH TECH</div></div>

<div id="shm" class="modal-back hidden"><div class="modal"><div class="display" style="font-size:18px">Share parcel</div>
<div id="sh0"><div class="hint">Create a public link anyone can open.</div><div class="field" style="text-align:left"><label>Link expires</label><select id="exp" style="width:100%;padding:10px;border:1.5px solid var(--ink);background:var(--surface);border-radius:3px"><option value="0">Never</option><option value="1">1 day</option><option value="7">7 days</option><option value="30">30 days</option></select></div><button class="btn stamp block" id="mk">Create share link</button></div>
<div id="sh1" class="hidden"><div class="code mono" id="sc"></div><div class="qr" id="sq" style="width:150px;height:150px;display:flex;align-items:center;justify-content:center;background:#fff"></div>
<div class="link-row"><button class="btn teal" id="cs">Copy share link</button><a class="btn ghost" id="op" target="_blank" style="text-decoration:none">Open preview</a><button class="btn ghost" id="un">Stop sharing</button></div></div>
<button class="btn ghost block" id="shx" style="margin-top:10px">Done</button></div></div>

<div id="edm" class="modal-back hidden"><div class="modal" style="text-align:left"><div class="display" style="font-size:18px;text-align:center;margin-bottom:14px">Edit parcel</div>
<div class="field"><label>Name</label><input type="text" id="en"></div><div class="field"><label>Description</label><textarea id="ed2"></textarea></div>
<div class="two-col"><div class="field"><label>Tags</label><input type="text" id="et" placeholder="comma, separated"></div><div class="field"><label>Share code</label><input type="text" id="ec2"></div></div>
<div class="intake-actions"><button class="btn ghost" id="edx">Cancel</button><button class="btn stamp" id="eds">Save</button></div></div></div>

<div id="cmm" class="modal-back hidden"><div class="modal" style="text-align:left"><div class="display" style="font-size:18px;text-align:center">Comments</div>
<div id="cml" style="display:flex;flex-direction:column;gap:8px;margin:16px 0;max-height:45vh;overflow:auto"></div>
<div class="field"><label>Reply</label><textarea id="cmt" placeholder="Write a reply…"></textarea></div><button class="btn teal block" id="cms" style="margin-bottom:10px">Post reply</button><button class="btn ghost block" id="cmx">Close</button></div></div>

<div id="em" class="modal-back hidden"><div class="modal" style="max-width:460px"><div class="display" style="font-size:18px">Edit image</div>
<div class="row"><div class="cw" id="cw"><canvas id="ec"></canvas><div id="cr"></div></div></div>
<div class="row"><button class="btn ghost sm" data-a2="rl">⟲ Rotate</button><button class="btn ghost sm" data-a2="rr">⟳ Rotate</button><button class="btn ghost sm" data-a2="fh">⇋ Flip</button>
<button class="btn ghost sm" data-r="0">Free</button><button class="btn ghost sm" data-r="1">1:1</button><button class="btn ghost sm" data-r="1.3333">4:3</button><button class="btn ghost sm" data-r="1.7778">16:9</button><button class="btn ghost sm" id="ac">✂ Crop</button></div>
<div class="row"><label>Width <input id="rw" type="number" min="16" style="width:80px;padding:5px;border:1.5px solid var(--ink);background:var(--surface);color:var(--ink)"></label><label>☀<input type="range" id="fb" min="50" max="150" value="100"></label><label>◐<input type="range" id="fc" min="50" max="150" value="100"></label><label>🎨<input type="range" id="fs" min="0" max="200" value="100"></label></div>
<div class="intake-actions"><button class="btn ghost" id="exx">Cancel</button><button class="btn ghost" id="er">Reset</button><button class="btn stamp" id="ed">Apply</button></div></div></div>

<div id="fulm" class="modal-back hidden"><div class="modal"><div style="font-size:58px">🚫</div>
<div class="display" style="font-size:30px;color:var(--stamp);letter-spacing:.08em">Storage full</div>
<p style="font-size:14px;margin:10px 0 16px">Your upload was paused because you've used all <b>{{ hs(cap) }}</b>. Free up space, or get more storage in seconds.</p>
<a class="btn stamp block" href="/plans" style="text-decoration:none">See plans →</a><a class="btn ghost block" href="/?k=trash" style="margin-top:8px;text-decoration:none">Free up space</a>
<button class="btn ghost block" id="fulx" style="margin-top:8px;border-color:transparent">Close</button></div></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<script>const CSRF="{{ session.csrf }}",S3={{ s3|tojson }},ITEMS={{ items|tojson }},K="{{ k }}",PER={{ per_gb }};</script>
{% raw %}<script>
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const post=(u,b,h={})=>fetch(u,{method:'POST',headers:{'X-CSRF':CSRF,...h},body:b});
const pj=(u,o)=>post(u,JSON.stringify(o),{'Content-Type':'application/json'});
const hid=(s,on)=>$(s).classList.toggle('hidden',!on);
const hs=n=>n<1024?n+' B':n<1048576?(n/1024).toFixed(1)+' KB':n<1073741824?(n/1048576).toFixed(1)+' MB':(n/1073741824).toFixed(2)+' GB';
function toast(m,undo){const t=document.createElement('div');t.className='toast';t.textContent=m;document.body.append(t);setTimeout(()=>t.remove(),3000)}
const copy=u=>(navigator.clipboard?navigator.clipboard.writeText(u).then(()=>toast('Link copied')):Promise.reject()).catch(()=>prompt('Copy link',u));
const tg=()=>{const d=document.documentElement,n=d.dataset.theme==='dark'?'light':'dark';d.dataset.theme=n;try{localStorage.setItem('theme',n)}catch(e){}};
$('#themeb').onclick=tg;$('#mmb').onclick=e=>{e.stopPropagation();$('#mm').classList.toggle('hidden')};document.addEventListener('click',e=>{if(!e.target.closest('#mm'))$('#mm').classList.add('hidden')});
const eb=$('#emptyb');if(eb)eb.onclick=()=>confirm('Delete everything in Trash forever?')&&post('/empty-trash').then(()=>location.reload());
/* selection */
const sel=new Set();let selMode=0;
function selUpdate(){$('#bulkbar').classList.toggle('show',selMode);$('#bc').textContent=sel.size+' selected';$('#selb').textContent=selMode?'Cancel':'Select';
 $$('.card').forEach(c=>{const on=sel.has(+c.dataset.id);c.classList.toggle('sel',on);const k=c.querySelector('.select-check');k.classList.toggle('hidden',!selMode);k.checked=on})}
$('#selb').onclick=()=>{selMode=!selMode;if(!selMode)sel.clear();selUpdate()};
async function bulk(a,extra={}){if(!sel.size)return;await pj('/api/bulk',{ids:[...sel],action:a,...extra});location.reload()}
function bulkTag(){const t=prompt('Tags to add (comma separated)');if(t)bulk('tag',{tags:t})}
/* cards */
let mi=0;
$('#grid').onclick=async e=>{const c=e.target.closest('.card');if(!c)return;const id=+c.dataset.id,i=+c.dataset.i,x=ITEMS[i],b=e.target.closest('[data-a]');
 if(selMode){if(e.target.closest('a'))e.preventDefault();sel.has(id)?sel.delete(id):sel.add(id);selUpdate();return}
 const a=b&&b.dataset.a;if(!a)return;
 if(a==='pv')location.href='/?item='+x.sid;
 else if(a==='sh')openShare(i);
 else if(a==='fv'){e.stopPropagation();await post('/fav/'+id);x.f=!x.f;b.textContent=x.f?'★':'☆'}
 else if(a==='ed'){mi=i;$('#en').value=x.n;$('#ed2').value=x.ds||'';$('#et').value=x.t||'';$('#ec2').value=x.sid;hid('#edm',1)}
 else if(a==='cm')openCm(i);
 else if(a==='rs'){await post('/restore/'+id);c.remove();toast('Restored')}
 else if(a==='rm'){if(!confirm(K==='trash'?'Delete forever?':'Move to Trash?'))return;await post(K==='trash'?'/purge/'+id:'/trash/'+id);c.remove();toast(K==='trash'?'Deleted':'Moved to Trash')}};
/* share modal */
function openShare(i){mi=i;const x=ITEMS[i];hid('#sh0',!x.u);hid('#sh1',!!x.u);if(x.u){$('#sc').textContent=x.sid;$('#op').href=x.u;const q=$('#sq');q.innerHTML='';try{new QRCode(q,{text:x.u,width:140,height:140})}catch(e){}}hid('#shm',1)}
$('#mk').onclick=async()=>{const x=ITEMS[mi],r=await post('/share/'+x.id,new URLSearchParams({days:$('#exp').value}));x.u=(await r.json()).url;openShare(mi)};
$('#un').onclick=async()=>{const x=ITEMS[mi];await post('/unshare/'+x.id);x.u='';openShare(mi);toast('Sharing stopped')};
$('#cs').onclick=()=>copy(ITEMS[mi].u);$('#shx').onclick=()=>hid('#shm',0);
/* edit modal */
$('#edx').onclick=()=>hid('#edm',0);
$('#eds').onclick=async()=>{const x=ITEMS[mi],r=await pj('/api/meta/'+x.id,{name:$('#en').value,description:$('#ed2').value,tags:$('#et').value,code:$('#ec2').value}),j=await r.json();if(!r.ok)return toast(j.error||'Could not save');location.reload()};
/* comments */
async function openCm(i){mi=i;hid('#cmm',1);const l=$('#cml');l.textContent='Loading…';const r=await fetch('/api/comments/'+ITEMS[i].id),j=await r.json();l.innerHTML='';
 if(!j.length)l.innerHTML='<div class="hint">No comments yet.</div>';
 j.forEach(c=>{const d=document.createElement('div');d.className='cm-i';const h=document.createElement('div');h.className='hb2';const n=document.createElement('b');n.textContent=(c.name||'Anonymous')+(c.own?' · you':'');const dl=document.createElement('button');dl.className='btn ghost sm';dl.textContent='Delete';dl.onclick=async()=>{await post('/api/comment-del/'+c.id);openCm(mi)};h.append(n,dl);const t=document.createElement('div');t.textContent=c.body;d.append(h,t);l.append(d)})}
$('#cms').onclick=async()=>{const t=$('#cmt').value.trim();if(!t)return;await pj('/api/comment/'+ITEMS[mi].sid,{text:t});$('#cmt').value='';openCm(mi)};$('#cmx').onclick=()=>hid('#cmm',0);
/* compression */
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
/* intake queue */
const S=[];
$('#newb').onclick=()=>{$('#intake').classList.toggle('hidden');window.scrollTo(0,0)};$('#cancelb').onclick=()=>{if(!S.some(s=>s.busy))hid('#intake',0)};
$$('.tab-btn').forEach(b=>b.onclick=()=>{$$('.tab-btn').forEach(x=>x.classList.remove('active'));b.classList.add('active');$('#pick').accept=b.dataset.t==='*/*'?'':b.dataset.t});
$('#dz').onclick=()=>$('#pick').click();$('#pick').onclick=e=>e.stopPropagation();
function addFiles(fl){[...fl].forEach(f=>{const m=/^(.*?)(\.[^.]+)?$/.exec(f.name),k=f.type.startsWith('image/')?'image':f.type.startsWith('video/')?'video':'file';
 const st={blob:f,base:m[1]||'file',ext:m[2]||'',kind:k,shrink:true,orig:f.size},r=document.createElement('div');S.push(st);r.className='qrow';
 r.innerHTML='<div class="qt"></div><div class="qm"><div class="qn"><input type="text" class="nm"><span class="ex ss"></span></div><div class="ss sz"></div><div class="pb"><i></i></div></div><label class="ss" style="text-transform:none;letter-spacing:0"><input type="checkbox" class="sk" checked> shrink</label><button class="btn ghost sm ed" title="Edit">✎</button><button class="btn ghost sm rm" title="Remove">✕</button>';
 st.el=r;const nm=r.querySelector('.nm');nm.value=st.base;nm.oninput=e=>st.base=e.target.value;r.querySelector('.sk').onchange=e=>st.shrink=e.target.checked;
 r.querySelector('.rm').onclick=()=>{S.splice(S.indexOf(st),1);r.remove()};const ed=r.querySelector('.ed');
 if(k!=='image'||/gif|svg/.test(f.type))ed.style.visibility='hidden';else ed.onclick=()=>load(st);
 $('#ql').append(r);refresh(st)})}
function refresh(st){const r=st.el,q=r.querySelector('.qt');r.querySelector('.ex').textContent=st.ext;r.querySelector('.sz').textContent=hs(st.blob.size)+(st.blob.size!==st.orig?' (was '+hs(st.orig)+')':'');
 const u=URL.createObjectURL(st.blob);q.innerHTML='';if(st.kind==='image'){const i=new Image();i.src=u;q.append(i)}else if(st.kind==='video'){const v=document.createElement('video');v.src=u+'#t=0.1';v.muted=true;v.preload='metadata';q.append(v)}else q.textContent='📄'}
$('#pick').onchange=e=>{addFiles(e.target.files);e.target.value=''};
['dragover','drop'].forEach(n=>document.addEventListener(n,e=>{e.preventDefault();$('#dz').classList.toggle('drag-over',n==='dragover');if(n==='drop'&&e.dataTransfer.files.length){hid('#intake',1);addFiles(e.dataTransfer.files)}}));
function xhr(method,url,body,type,cb){return new Promise((ok,no)=>{const x=new XMLHttpRequest();x.open(method,url);if(type)x.setRequestHeader('Content-Type',type);x.setRequestHeader('X-CSRF',CSRF);
 x.upload.onprogress=e=>e.lengthComputable&&cb(e.loaded/e.total);
 x.onload=()=>x.status<300?ok():no(new Error((()=>{try{const d=JSON.parse(x.responseText);if(d.full)openPlans();return d.error}catch(e){return 'Upload failed'}})()));x.onerror=()=>no(new Error('Network error — check bucket CORS'));x.send(body)})}
async function upOne(b,name,cb){const type=b.type||'application/octet-stream',meta={description:$('#desc').value,tags:$('#tags').value};
 if(S3){const r=await pj('/api/presign',{name,type,size:b.size,...meta}),j=await r.json();if(!r.ok){if(j.full)openPlans();throw new Error(j.error)}
  await xhr('PUT',j.url,b,type,cb);const d=await post('/api/done/'+j.id);if(!d.ok)throw new Error('Could not finish upload')}
 else{const fd=new FormData();fd.append('file',b,name);fd.append('description',meta.description);fd.append('tags',meta.tags);await xhr('POST','/upload',fd,null,cb)}}
$('#ug').onclick=async()=>{if(!S.length)return;$('#ug').disabled=true;let ok=0;const q=Q[$('#qs').value];
 for(const st of S){if(st.done)continue;st.busy=1;const r=st.el,ss=r.querySelector('.sz'),bar=r.querySelector('.pb i');
  try{let b=st.blob;
   if(st.shrink&&q){ss.textContent='Shrinking…';if(st.kind==='image'&&!/gif|svg/.test(b.type))b=await shrinkImg(b,q);else if(st.kind==='video')b=await shrinkVid(b,q,p=>{ss.textContent='Shrinking video '+Math.round(p*100)+'%'})}
   const ext=b!==st.blob?(EX[b.type]||st.ext):st.ext,name=(st.base.trim()||'file')+ext;
   ss.textContent='Uploading '+hs(st.orig)+' → '+hs(b.size);await upOne(b,name,p=>bar.style.width=Math.round(p*100)+'%');
   bar.style.width='100%';ss.textContent='✓ Shipped · '+hs(b.size);st.done=1;ok++}catch(e){ss.textContent='⚠ '+e.message}st.busy=0}
 $('#ug').disabled=false;if(ok){$('#us').textContent=ok+' parcel(s) shipped';setTimeout(()=>location.reload(),800)}};
function openPlans(){hid('#fulm',1)}$('#fulx').onclick=()=>hid('#fulm',0);
/* image editor */
let E=null,d0=null;const cw=$('#cw'),cv=$('#ec'),cr=$('#cr');
const flt=()=>`brightness(${$('#fb').value}%) contrast(${$('#fc').value}%) saturate(${$('#fs').value}%)`;
function load(st){const im=new Image();im.onload=()=>{const c=document.createElement('canvas');c.width=im.naturalWidth;c.height=im.naturalHeight;c.getContext('2d').drawImage(im,0,0);E={st,base:c,crop:null,asp:0};['#fb','#fc','#fs'].forEach(s=>$(s).value=100);draw();hid('#em',1)};im.src=URL.createObjectURL(st.blob)}
function draw(){const b=E.base;cv.width=b.width;cv.height=b.height;cv.getContext('2d').drawImage(b,0,0);cv.style.filter=flt();$('#rw').value=b.width;E.crop=null;cr.style.display='none'}
['#fb','#fc','#fs'].forEach(s=>$(s).oninput=()=>cv.style.filter=flt());
function tf(fn){const c=document.createElement('canvas');fn(E.base,c);E.base=c;draw()}
function rot(d){tf((b,c)=>{c.width=b.height;c.height=b.width;const x=c.getContext('2d');x.translate(c.width/2,c.height/2);x.rotate(d*Math.PI/2);x.drawImage(b,-b.width/2,-b.height/2)})}
function flip(){tf((b,c)=>{c.width=b.width;c.height=b.height;const x=c.getContext('2d');x.translate(b.width,0);x.scale(-1,1);x.drawImage(b,0,0)})}
function setCrop(x,y,w,h){const r=cv.getBoundingClientRect();x=Math.max(0,x);y=Math.max(0,y);w=Math.min(w,r.width-x);h=Math.min(h,r.height-y);Object.assign(cr.style,{display:'block',left:x+'px',top:y+'px',width:w+'px',height:h+'px'});const s=cv.width/r.width;E.crop={x:x*s,y:y*s,w:w*s,h:h*s}}
cw.onpointerdown=e=>{const r=cv.getBoundingClientRect();d0={x:e.clientX-r.left,y:e.clientY-r.top,r};cw.setPointerCapture(e.pointerId)};
cw.onpointermove=e=>{if(!d0)return;const r=d0.r,x=Math.min(Math.max(e.clientX-r.left,0),r.width),y=Math.min(Math.max(e.clientY-r.top,0),r.height);let w=x-d0.x,h=y-d0.y;if(E.asp)h=(h<0?-1:1)*Math.abs(w)/E.asp;setCrop(Math.min(d0.x,d0.x+w),Math.min(d0.y,d0.y+h),Math.abs(w),Math.abs(h))};
cw.onpointerup=()=>d0=null;
$$('[data-a2]').forEach(b=>b.onclick=()=>{const a=b.dataset.a2;a==='rl'?rot(-1):a==='rr'?rot(1):flip()});
$$('[data-r]').forEach(b=>b.onclick=()=>{const v=b.dataset.r;E.asp=+v;if(!E.asp){E.crop=null;cr.style.display='none';return}const r=cv.getBoundingClientRect();let w=r.width,h=w/E.asp;if(h>r.height){h=r.height;w=h*E.asp}setCrop((r.width-w)/2,(r.height-h)/2,w,h)});
function applyCrop(){const k=E.crop;if(!k||k.w<8||k.h<8)return;tf((b,c)=>{c.width=Math.round(k.w);c.height=Math.round(k.h);c.getContext('2d').drawImage(b,k.x,k.y,k.w,k.h,0,0,c.width,c.height)})}
$('#ac').onclick=applyCrop;$('#exx').onclick=()=>hid('#em',0);$('#er').onclick=()=>load(E.st);
$('#ed').onclick=()=>{applyCrop();const b=E.base,W=Math.max(16,+$('#rw').value||b.width),H=Math.round(b.height*W/b.width),c=document.createElement('canvas');c.width=W;c.height=H;
 const x=c.getContext('2d');x.filter=flt();x.drawImage(b,0,0,W,H);c.toBlob(o=>{E.st.blob=o;E.st.ext=EX[WEBP];refresh(E.st);hid('#em',0)},WEBP,.92)};
</script>{% endraw %}
"""

ITEM = r"""<div class="screen"><div class="pub-wrap" style="width:100%">
{% if owner %}<p style="margin:0 0 12px;font-size:13px"><a href="/">← Back to manifest</a>{% if not shared %} · <span class="hint">Private — only you can see this until you share it</span>{% endif %}</p>{% endif %}
<div class="pub-card"><div class="pub-media">{% if f.kind=='image' %}<img src="/raw/{{f.sid}}" alt="">{% elif f.kind=='video' %}<video src="/raw/{{f.sid}}" controls playsinline></video>{% else %}<div style="font-size:64px;padding:40px">📄</div>{% endif %}</div>
<div class="pub-body"><div class="stamp-tag" style="position:static;display:inline-block;transform:rotate(-2deg);margin-bottom:10px">{{ f.kind|upper }}</div>
<p style="font-size:15px;line-height:1.5">{{ f.description or '(no description)' }}</p>
{% if tags %}<div class="tag-pills" style="margin-bottom:10px">{% for t in tags %}<span class="tag-pill">{{t}}</span>{% endfor %}</div>{% endif %}
<div class="card-meta"><span>{{ f.name }}</span><span>{{ dt }}</span></div>
<div id="rx" style="display:flex;gap:6px;flex-wrap:wrap;margin-top:12px">{% for e in emojis %}<button type="button" class="btn ghost sm" data-e="{{e}}" style="padding:6px 10px;{{ 'background:var(--ink);color:var(--tag);' if e in mine }}">{{e}} <span>{{ rx.get(e) or '' }}</span></button>{% endfor %}</div>
<a class="btn ghost block" style="margin-top:14px;text-decoration:none" href="/raw/{{f.sid}}?dl=1">⬇ Download</a></div></div>
<div class="pub-card" style="margin-top:14px;padding:16px"><div class="section-title" style="font-size:13px">Comments</div>
<div style="display:flex;flex-direction:column;gap:10px;margin:12px 0">{% for c in comments %}<div class="cm-i"><div class="hb2"><b>{{ c.name or 'Anonymous' }}{% if c.is_owner %} <span style="color:var(--stamp)">· owner</span>{% endif %}</b><span>{{ c.dt }}</span></div><div style="word-break:break-word">{{ c.body }}</div></div>{% endfor %}{% if not comments %}<div class="hint">No comments yet.</div>{% endif %}</div>
<div class="field" style="margin-bottom:8px"><input type="text" id="cn" placeholder="Your name (optional)" maxlength="40"></div>
<div class="field"><textarea id="ct" placeholder="Leave a comment…" style="min-height:60px"></textarea></div><button type="button" class="btn stamp block" id="cb">Post comment</button></div>
<div class="pub-foot">Shipped via <strong>YIM CLOUD STORAGE</strong> · <a href="/">open the store</a><br>DEVELOPED BY SYMOH TECH</div></div></div>
<script>const CSRF="{{ session.csrf }}",SID="{{ f.sid }}";
{% raw %}const pj=(u,o)=>fetch(u,{method:'POST',headers:{'X-CSRF':CSRF,'Content-Type':'application/json'},body:JSON.stringify(o)});
document.querySelectorAll('#rx button').forEach(b=>b.onclick=async()=>{const r=await pj('/api/react/'+SID,{emoji:b.dataset.e});if(!r.ok)return;const j=await r.json();b.querySelector('span').textContent=j.n||'';b.style.background=j.on?'var(--ink)':'';b.style.color=j.on?'var(--tag)':''});
document.getElementById('cb').onclick=async()=>{const t=document.getElementById('ct').value.trim();if(!t)return;const r=await pj('/api/comment/'+SID,{text:t,name:document.getElementById('cn').value});if(r.ok)location.reload()};
</script>{% endraw %}
"""

ORDER = {"new": "created_at DESC", "old": "created_at ASC", "big": "size DESC", "name": "lower(name) ASC"}

EMOJIS = ["👍", "❤️", "😂", "🎉", "😮", "😢"]

def clean_tags(t):
    out = []
    for x in str(t or "").split(","):
        x = x.strip()[:24]
        if x and x.lower() not in [y.lower() for y in out]: out.append(x)
    return ",".join(out[:12]) or None

def find_item(sid):
    sid = (sid or "").strip().lower()[:40]
    return q("SELECT id,user_id,name,mime,kind,size,description,tags,created_at,sid,share_slug,share_expires_at,trashed_at FROM files WHERE ready AND (sid=%s OR share_slug=%s)", (sid, sid), one=True)

def visible(f):
    if session.get("uid") == f["user_id"]: return True
    return bool(f["share_slug"]) and not f["trashed_at"] and (not f["share_expires_at"] or f["share_expires_at"] > datetime.now(timezone.utc))

def item_page(sid):
    f = find_item(sid)
    if not f or not visible(f): abort(404)
    owner = session.get("uid") == f["user_id"]
    if not owner: q("UPDATE files SET share_views=share_views+1, share_last_view=now() WHERE id=%s", (f["id"],))
    rx = {r["emoji"]: r["n"] for r in q("SELECT emoji,n FROM reactions WHERE file_id=%s AND n>0", (f["id"],))}
    mine = [e for e in EMOJIS if f"{f['sid']}:{e}" in session.get("r", [])]
    cms = q("SELECT name,body,is_owner,created_at FROM comments WHERE file_id=%s ORDER BY created_at", (f["id"],))
    for c in cms: c["dt"] = c["created_at"].strftime("%d/%m/%Y")
    head = f'<meta property="og:title" content="{escape(f["name"])}"><meta property="og:description" content="{escape(f["description"] or "Shared via YIM CLOUD STORAGE")}">'
    if f["kind"] == "image": head += f'<meta property="og:image" content="{escape(base_url())}/raw/{f["sid"]}">'
    return page(ITEM, f["name"] + " · YIM CLOUD STORAGE", full=True, head=head, f=f, owner=owner, shared=bool(f["share_slug"]), emojis=EMOJIS,
                rx=rx, mine=mine, comments=cms, tags=(f["tags"] or "").split(",") if f["tags"] else [], dt=f["created_at"].strftime("%d/%m/%Y"))

@app.route("/raw/<sid>")
def raw(sid):
    f = find_item(sid)
    if not f or not visible(f): abort(404)
    return send_row(f["id"], bool(request.args.get("dl")))

@app.route("/s/<slug>")
def shared(slug): return redirect(url_for("home", item=slug))

@app.route("/api/react/<sid>", methods=["POST"])
def react(sid):
    f, e = find_item(sid), (request.get_json(silent=True) or {}).get("emoji")
    if not f or not visible(f) or e not in EMOJIS: abort(400)
    key, mine = f"{f['sid']}:{e}", session.get("r", [])
    on = key not in mine
    session["r"] = (mine + [key] if on else [k for k in mine if k != key])[-60:]
    row = q("INSERT INTO reactions(file_id,emoji,n) VALUES(%s,%s,%s) ON CONFLICT(file_id,emoji) DO UPDATE SET n=GREATEST(reactions.n+%s,0) RETURNING n",
            (f["id"], e, 1 if on else 0, 1 if on else -1), one=True)
    return {"n": row["n"], "on": on}

@app.route("/api/comment/<sid>", methods=["POST"])
def comment(sid):
    f, j = find_item(sid), request.get_json(silent=True) or {}
    t = str(j.get("text", "")).strip()[:1000]
    if not f or not visible(f) or not t: return {"error": "Write a comment first."}, 400
    own_ = session.get("uid") == f["user_id"]
    q("INSERT INTO comments(file_id,name,body,is_owner) VALUES(%s,%s,%s,%s)",
      (f["id"], (session.get("uname") if own_ else str(j.get("name", "")).strip()[:40]) or None, t, own_))
    return {"ok": True}

@app.route("/api/comments/<int:fid>")
@login_required
def comments_list(fid):
    own(fid)
    return [{"id": c["id"], "name": c["name"], "body": c["body"], "own": c["is_owner"]} for c in
            q("SELECT id,name,body,is_owner FROM comments WHERE file_id=%s ORDER BY created_at", (fid,))]

@app.route("/api/comment-del/<int:cid>", methods=["POST"])
@login_required
def comment_del(cid):
    q("DELETE FROM comments WHERE id=%s AND file_id IN (SELECT id FROM files WHERE user_id=%s)", (cid, session["uid"])); return {"ok": True}

@app.route("/")
def home():
    if request.args.get("item"): return item_page(request.args["item"])
    u = user()
    if not u or u["blocked"]: session.clear(); return redirect(url_for("login"))
    k, qs, o = request.args.get("k", "all"), request.args.get("s", "").strip(), request.args.get("o", "new")
    if o not in ORDER: o = "new"
    where, args = "user_id=%s AND ready", [session["uid"]]
    where += " AND trashed_at IS NOT NULL" if k == "trash" else " AND trashed_at IS NULL"
    if k == "fav": where += " AND favorite"
    if k in ("image", "video", "file"): where += " AND kind=%s"; args.append(k)
    if qs: where += " AND (name ILIKE %s OR description ILIKE %s OR tags ILIKE %s)"; args += [f"%{qs}%"] * 3
    rows = q(f"SELECT id,name,kind,size,favorite,share_slug,share_views,share_last_view,description,tags,sid,created_at FROM files WHERE {where} ORDER BY {ORDER[o]}", args)
    used, base = used_bytes(session["uid"]), base_url()
    items = []
    for r in rows:
        r["i"] = len(items)
        r["dt"] = r["created_at"].strftime("%d/%m/%Y")
        r["lv"] = r["share_last_view"].strftime("%d/%m/%Y") if r["share_last_view"] else "never viewed"
        r["tagl"] = r["tags"].split(",") if r["tags"] else []
        items.append({"id": r["id"], "n": r["name"], "ds": r["description"] or "", "t": r["tags"] or "", "k": r["kind"], "s": human(r["size"]),
                      "f": bool(r["favorite"]), "sid": r["sid"], "u": f"{base}/?item={r['sid']}" if r["share_slug"] else ""})
    last = max((r["created_at"] for r in rows), default=None)
    pl, per = plans()
    return page(DASH, "YIM CLOUD STORAGE", full=True, rows=rows, items=items, k=k, qs=qs, o=o, used=used, cap=u["quota_bytes"], plans=pl, per_gb=per, admin=is_admin(u),
                hs=human, s3=S3_ON, last=last.strftime("%d/%m/%Y") if last else "—", fl=get_flashed_messages(with_categories=True))

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
    elif a == "tag":
        add = (clean_tags(j.get("tags")) or "").split(",")
        for r in q("SELECT id,tags FROM files WHERE id=ANY(%s)", (ids,)):
            q("UPDATE files SET tags=%s WHERE id=%s", (clean_tags(",".join(filter(None, (r["tags"] or "").split(",") + add))), r["id"]))
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
    if used_bytes(session["uid"]) + size > user()["quota_bytes"]: return {"error": "Storage full — pick a plan to keep uploading.", "full": True}, 402
    key = f"u{session['uid']}/{secrets.token_hex(8)}-{re.sub(r'[^A-Za-z0-9._-]', '_', name)}"
    r = q("INSERT INTO files(user_id,name,mime,kind,size,s3_key,ready,sid,description,tags) VALUES(%s,%s,%s,%s,%s,%s,FALSE,%s,%s,%s) RETURNING id",
          (session["uid"], name, mime, kind_of(mime), size, key, secrets.token_hex(5), str(j.get("description", "")).strip()[:300] or None, clean_tags(j.get("tags"))), one=True)
    return {"id": r["id"], "url": presign("put_object", key, 3600, ContentType=mime)}

@app.route("/api/done/<int:fid>", methods=["POST"])
@login_required
def api_done(fid):
    f = own(fid)
    try: head = s3().head_object(Bucket=os.environ["S3_BUCKET"], Key=f["s3_key"])
    except Exception: abort(400, "Upload missing")
    q("UPDATE files SET ready=TRUE,size=%s WHERE id=%s", (head["ContentLength"], fid)); log_act(session["uid"], "upload", f["name"]); return {"ok": True}

@app.route("/upload", methods=["POST"])  # fallback when S3 is not configured
@login_required
def upload():
    f = request.files.get("file")
    if S3_ON or not f: abort(400)
    data = f.read()
    mime = f.mimetype or mimetypes.guess_type(f.filename)[0] or "application/octet-stream"
    if used_bytes(session["uid"]) + len(data) > user()["quota_bytes"]: return {"error": "Storage full — pick a plan to keep uploading.", "full": True}, 402
    q("INSERT INTO files(user_id,name,mime,kind,size,data,sid,description,tags) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)",
      (session["uid"], os.path.basename(f.filename)[:200], mime, kind_of(mime), len(data), psycopg2.Binary(data), secrets.token_hex(5),
       request.form.get("description", "").strip()[:300] or None, clean_tags(request.form.get("tags"))))
    return {"ok": True}

@app.route("/f/<int:fid>")
@login_required
def serve(fid):
    own(fid); return send_row(fid, bool(request.args.get("dl")))

@app.route("/share/<int:fid>", methods=["POST"])
@login_required
def share(fid):
    f = own(fid); d = int(request.form.get("days", 0))
    q("UPDATE files SET share_slug=sid, share_expires_at=CASE WHEN %s>0 THEN now()+%s*interval '1 day' END WHERE id=%s", (d, d, fid))
    if request.headers.get("X-CSRF"): return {"url": f"{base_url()}/?item={f['sid']}"}
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

@app.route("/api/meta/<int:fid>", methods=["POST"])
@login_required
def api_meta(fid):
    f = own(fid); j = request.get_json(silent=True) or {}
    n = os.path.basename(str(j.get("name", "")).strip())[:200]
    if not n: return {"error": "Name required"}, 400
    code = re.sub(r"[^a-z0-9]", "", str(j.get("code") or f["sid"]).lower())[:32]
    if len(code) < 4: return {"error": "Share code needs at least 4 letters/numbers."}, 400
    if code != f["sid"] and q("SELECT 1 FROM files WHERE (sid=%s OR share_slug=%s) AND id<>%s", (code, code, fid), one=True):
        return {"error": "That share code is already taken."}, 400
    q("UPDATE files SET name=%s, description=%s, tags=%s, sid=%s, share_slug=CASE WHEN share_slug IS NULL THEN NULL ELSE %s END WHERE id=%s",
      (n, str(j.get("description", "")).strip()[:300] or None, clean_tags(j.get("tags")), code, code, fid))
    return {"ok": True}

# ---------- settings, mail, plans, payments, admin ----------
PLANS_TPL = r"""<div class="app">
<div class="topbar"><div class="brand display">YIM <span>CLOUD STORAGE</span></div><span style="flex:1"></span><a class="btn ghost" href="/" style="text-decoration:none">← Back to store</a></div>
<div class="pl-hero {{ state }}"><div class="display pl-h">{{ '🚫 STORAGE FULL' if state=='full' else '⚠ ALMOST FULL' if state=='warn' else 'GET MORE STORAGE' }}</div>
<p style="margin:8px auto 0;max-width:560px;font-size:14px">{{ msg }}</p>
<div class="pl-meter"><i style="width:{{pct}}%"></i></div><div class="pl-m2"><span>{{ hs(used) }} used</span><span>{{pct}}% of {{ hs(cap) }}</span></div></div>

<div class="section-title">Choose a plan</div>
<div class="pl-grid">
{% for p in cards %}<div class="pl-card" data-id="{{p.id}}" data-gb="{{p.gb}}" data-price="{{p.price}}">{% if p.best %}<div class="pl-ribbon">Best value</div>{% endif %}
<div><span class="stamp-tag" style="position:static;display:inline-block;transform:rotate(-3deg)">{{p.name}}</span></div>
<div class="display pl-gb">{{p.gb}} <small>GB</small></div><div class="pl-price">KSh {{p.price}}</div><div class="pl-per">≈ KSh {{p.per}} per GB · one-time</div>
<p class="pl-d">{{p.desc}}</p><ul class="pl-ul"><li>≈ {{p.photos}} photos</li><li>≈ {{p.hours}} hours of video</li><li>Added to your account instantly</li></ul>
<button class="btn stamp block pl-pick">Choose {{p.gb}} GB</button></div>{% endfor %}
<div class="pl-card" data-id="custom"><div><span class="stamp-tag" style="position:static;display:inline-block;transform:rotate(-3deg)">YOUR SIZE</span></div>
<div class="display pl-gb"><input type="number" id="cg" min="1" max="1000" value="10" style="width:90px;font:inherit;text-align:center;border:2px solid var(--ink);background:var(--surface);color:var(--ink);border-radius:4px"> <small>GB</small></div>
<div class="pl-price" id="cp"></div><div class="pl-per">KSh {{per}} per GB · one-time</div>
<p class="pl-d">Need something in between? Pick exactly the size you need, from 1 to 1000 GB.</p><div class="pl-tip" id="ch"></div>
<ul class="pl-ul"><li>Any size you like</li><li>Stacks on top of your storage</li><li>Added to your account instantly</li></ul>
<button class="btn stamp block pl-pick">Choose custom size</button></div>
</div>

<div class="intake hidden" id="ck" style="margin-top:18px"><div class="section-title">Checkout</div>
<div id="sm" style="font-size:16px;margin:6px 0 12px"></div>
<div class="field"><label>M-Pesa number</label><input type="text" id="ph" inputmode="tel" placeholder="07xx xxx xxx" style="width:100%;padding:10px 12px;border:1.5px solid var(--ink);border-radius:3px;background:var(--surface);color:var(--ink)"></div>
<div class="hint" style="text-align:left">You'll get an M-Pesa prompt on this number. Enter your PIN to pay — your storage is added automatically.</div>
<div id="pm" style="font-weight:600;margin:10px 0"></div><div class="intake-actions"><button class="btn stamp" id="pb">Pay with M-Pesa</button></div></div>

<div class="section-title" style="margin-top:28px">How it works</div>
<div class="pl-f"><div><b>1 · Choose a plan</b>Pick 50 GB, 100 GB, or your own size.</div><div><b>2 · Pay with M-Pesa</b>Enter your number and approve the prompt on your phone.</div><div><b>3 · Storage added</b>Your new space appears in seconds, and we email you a receipt.</div></div>

<div class="section-title" style="margin-top:28px">Every plan includes</div>
<div class="pl-f">
<div><b>⚡ Instant activation</b>No waiting — storage is added as soon as the payment clears.</div>
<div><b>🗜 Auto-shrink</b>Photos and videos are shrunk before upload, so your GB go further.</div>
<div><b>🔗 Share links &amp; QR</b>Share any file with a link, a QR code and an optional expiry.</div>
<div><b>💬 Comments &amp; reactions</b>Visitors can react and comment on files you share.</div>
<div><b>🗑 Trash &amp; restore</b>Deleted something by mistake? Bring it back from Trash.</div>
<div><b>🔒 Private by default</b>Only the files you choose to share are public.</div>
<div><b>🏷 Tags &amp; search</b>Name, describe and tag files so you can find them fast.</div>
<div><b>♾ No expiry</b>Storage you buy stays on your account — it is a one-time top-up.</div></div>

<div class="section-title" style="margin-top:28px">Questions</div>
<details class="pl-q"><summary>Is this a subscription?</summary><p>No. Each purchase is a one-time top-up that is added to your storage and stays on your account. Buy more any time and it stacks.</p></details>
<details class="pl-q"><summary>How long until I get my storage?</summary><p>Usually within seconds of approving the M-Pesa prompt. This page updates by itself when the payment is confirmed.</p></details>
<details class="pl-q"><summary>I paid but my storage didn't change</summary><p>Wait a minute and refresh. If it still hasn't changed, contact the site admin with your M-Pesa receipt and they can add it for you.</p></details>
<details class="pl-q"><summary>How do I free up space instead?</summary><p>Delete files you don't need, then empty your <a href="/?k=trash">Trash</a> — files in Trash still count towards your storage until they are deleted forever.</p></details>
<div class="pub-foot" style="margin-top:30px">DEVELOPED BY SYMOH TECH</div></div>

<script>const CSRF="{{ session.csrf }}",PER={{ per }},PLANS={{ cards|tojson }};</script>
{% raw %}<script>
const $=s=>document.querySelector(s),pj=(u,o)=>fetch(u,{method:'POST',headers:{'X-CSRF':CSRF,'Content-Type':'application/json'},body:JSON.stringify(o)});
let pick=null;
function hint(){const g=Math.max(1,+$('#cg').value||0),pr=g*PER,b=PLANS.filter(p=>p.gb>=g&&p.price<=pr).sort((a,b)=>a.price-b.price)[0];
 $('#cp').textContent='KSh '+pr;$('#ch').textContent=b?`💡 The ${b.gb} GB plan costs KSh ${b.price} — ${b.price<pr?'more storage for less':'more storage for the same price'}.`:'';if(pick&&pick.id==='custom')choose($('[data-id=custom]'))}
$('#cg').oninput=hint;hint();
function choose(c){document.querySelectorAll('.pl-card').forEach(x=>x.classList.remove('sel'));c.classList.add('sel');
 pick=c.dataset.id==='custom'?{id:'custom',gb:Math.max(1,+$('#cg').value||0),price:Math.max(1,+$('#cg').value||0)*PER}:{id:c.dataset.id,gb:+c.dataset.gb,price:+c.dataset.price};
 $('#sm').innerHTML='<b>'+pick.gb+' GB</b> for <b>KSh '+pick.price+'</b>';$('#ck').classList.remove('hidden');$('#ck').scrollIntoView({behavior:'smooth',block:'center'})}
document.querySelectorAll('.pl-pick').forEach(b=>b.onclick=()=>choose(b.closest('.pl-card')));
$('#pb').onclick=async()=>{if(!pick)return;$('#pb').disabled=true;$('#pm').textContent='Sending M-Pesa prompt…';
 const r=await pj('/api/pay',{plan:pick.id,gb:pick.gb,phone:$('#ph').value}),j=await r.json();
 if(!r.ok){$('#pm').textContent='⚠ '+j.error;$('#pb').disabled=false;return}
 $('#pm').textContent='📲 Check your phone and enter your M-Pesa PIN to pay KSh '+j.amount+'…';let n=0;
 const t=setInterval(async()=>{n++;let s={};try{s=await (await fetch('/api/pay/'+j.id)).json()}catch(e){}
  if(s.status==='paid'){clearInterval(t);$('#pm').textContent='✅ Payment received! +'+j.gb+' GB added. Taking you back…';setTimeout(()=>location.href='/',1800)}
  else if(s.status==='failed'){clearInterval(t);$('#pm').textContent='⚠ Payment failed or was cancelled. '+(s.message||'')+' You can try again.';$('#pb').disabled=false}
  else if(n>45){clearInterval(t);$('#pm').textContent='Still waiting… if you paid, your storage will appear shortly.';$('#pb').disabled=false}},4000)};
</script>{% endraw %}
"""

@app.route("/plans")
@login_required
def plans_page():
    u = user(); used, cap = used_bytes(u["id"]), u["quota_bytes"]; pl, per = plans()
    pct = min(100, int(round(used * 100 / cap))) if cap else 100
    state = "full" if used >= cap else "warn" if used * 100 / cap >= 90 else "ok"
    msg = {"full": f"You've used all {human(cap)}. New uploads are paused until you free up space or add more storage.",
           "warn": f"You've used {pct}% of your {human(cap)}. Top up before you run out.",
           "ok": f"You're using {human(used)} of {human(cap)}. Add more any time — it stacks on top of what you already have."}[state]
    fmt = lambda x: f"{x:.2f}".rstrip("0").rstrip(".")
    descs = ["Great for everyday photos, screenshots and documents.", "Room for a whole library of photos, videos and big backups."]
    best = min(pl, key=lambda x: x["price"] / x["gb"])["id"]
    cards = [dict(p, name=("STARTER", "POWER")[i], per=fmt(p["price"] / p["gb"]), photos=f"{int(p['gb'] * 650):,}", hours=int(p["gb"] * 0.8),
                  desc=descs[i], best=p["id"] == best) for i, p in enumerate(sorted(pl, key=lambda x: x["gb"]))]
    return page(PLANS_TPL, "Storage plans · YIM CLOUD STORAGE", full=True, state=state, msg=msg, pct=pct, used=used, cap=cap, cards=cards, per=per, hs=human)

ADMIN_TPL = r"""<div class="app">
<div class="topbar"><div class="brand display">YIM <span>ADMIN</span></div><span style="flex:1"></span><a class="btn ghost" href="/" style="text-decoration:none">← Back to store</a></div>
<div class="stats-bar" style="flex-wrap:wrap;gap:14px 26px"><span><b>{{st.users}}</b> users</span><span><b>{{st.verified}}</b> verified</span><span><b>{{st.new7}}</b> new (7d)</span><span><b>{{st.files}}</b> files</span><span><b>{{hs(st.bytes)}}</b> stored</span><span><b>KSh {{st.revenue}}</b> revenue</span><span><b>{{st.pending}}</b> pending payments</span></div>

<div class="section-title">Payment settings (Techland M-Pesa)</div>
<div class="intake" style="display:block">
<div class="two-col"><div class="field"><label>API base URL</label><input type="text" data-k="pay_base" value="{{s.pay_base}}"></div><div class="field"><label>API key {{ '(saved ✓ — leave blank to keep)' if s.pay_key }}</label><input type="password" data-k="pay_key" placeholder="{{ '••••••••' if s.pay_key else 'tl_live_…' }}" autocomplete="off"></div></div>
<div class="field"><label>Webhook signing secret {{ '(saved ✓ — leave blank to keep)' if s.pay_whsec }}</label><input type="password" data-k="pay_whsec" placeholder="{{ '••••••••' if s.pay_whsec else 'From your Techland dashboard' }}" autocomplete="off"></div>
<div class="field"><label>Webhook URL — paste this in your Techland dashboard</label><input type="text" readonly value="{{ cb }}" onclick="this.select()"></div>
<div class="row" style="justify-content:flex-start"><button class="btn ghost" id="pt" type="button">Test API key</button><span class="hint" id="ptm">Save first, then test.</span></div>
<div class="section-title" style="font-size:13px">Plans &amp; free storage</div>
<div class="two-col"><div class="field"><label>Free GB for new users</label><input type="text" data-k="free_gb" value="{{s.free_gb}}"></div><div class="field"><label>Custom plan: KSh per GB</label><input type="text" data-k="per_gb" value="{{s.per_gb}}"></div></div>
<div class="two-col"><div class="field"><label>Plan 1: GB / KSh</label><div style="display:flex;gap:6px"><input type="text" data-k="p1_gb" value="{{s.p1_gb}}"><input type="text" data-k="p1_price" value="{{s.p1_price}}"></div></div><div class="field"><label>Plan 2: GB / KSh</label><div style="display:flex;gap:6px"><input type="text" data-k="p2_gb" value="{{s.p2_gb}}"><input type="text" data-k="p2_price" value="{{s.p2_price}}"></div></div></div>
<button class="btn stamp" id="sv">Save settings</button> <span class="hint" id="svm"></span></div>

<div class="section-title">Users</div>
<form method="get" style="margin-bottom:10px"><input type="text" name="s" value="{{qs}}" placeholder="Search username or email" style="max-width:340px"></form>
<div class="tw"><table class="at"><tr><th>User</th><th>Used / Quota</th><th>Files</th><th>Joined</th><th>Status</th><th>Actions</th></tr>
{% for u in users %}<tr><td><b>{{u.username}}</b><br><span class="mu2">{{u.email}}</span></td><td>{{hs(u.used)}} / {{hs(u.quota_bytes)}}</td><td>{{u.n}}</td><td>{{u.created_at.strftime('%d/%m/%Y')}}</td>
<td>{{ '✔ verified' if u.verified else '✖ unverified' }}{% if u.blocked %} · <b style="color:var(--stamp)">blocked</b>{% endif %}{% if u.is_admin %} · admin{% endif %}</td>
<td style="white-space:nowrap"><button class="btn ghost sm" onclick="addgb({{u.id}})">＋ GB</button> <button class="btn ghost sm" onclick="act({{u.id}},'{{ 'unblock' if u.blocked else 'block' }}')">{{ 'Unblock' if u.blocked else 'Block' }}</button> <button class="btn ghost sm" onclick="act({{u.id}},'{{ 'unadmin' if u.is_admin else 'admin' }}')">{{ 'Remove admin' if u.is_admin else 'Make admin' }}</button></td></tr>{% endfor %}</table></div>

<div class="section-title">Payments</div>
<div class="tw"><table class="at"><tr><th>When</th><th>User</th><th>Plan</th><th>Amount</th><th>Phone</th><th>Status</th><th></th></tr>
{% for p in pays %}<tr><td>{{p.created_at.strftime('%d/%m %H:%M')}}</td><td>{{p.username}}</td><td>{{p.gb}} GB</td><td>KSh {{p.amount}}</td><td>{{p.phone}}</td><td title="{{p.note or ''}}">{{p.status}}</td><td>{% if p.status!='paid' %}<button class="btn ghost sm" onclick="credit({{p.id}})">Mark paid</button>{% endif %}</td></tr>{% endfor %}
{% if not pays %}<tr><td colspan="7" class="mu2">No payments yet.</td></tr>{% endif %}</table></div>

<div class="section-title">Activity</div>
<div class="tw"><table class="at"><tr><th>When</th><th>User</th><th>Action</th><th>Detail</th></tr>{% for a in acts %}<tr><td>{{a.created_at.strftime('%d/%m %H:%M')}}</td><td>{{a.username or '—'}}</td><td>{{a.action}}</td><td>{{a.detail or ''}}</td></tr>{% endfor %}</table></div>
<div class="pub-foot" style="margin-top:30px">DEVELOPED BY SYMOH TECH</div></div>
<script>const CSRF="{{ session.csrf }}";
{% raw %}const pj=(u,o)=>fetch(u,{method:'POST',headers:{'X-CSRF':CSRF,'Content-Type':'application/json'},body:JSON.stringify(o)}).then(async r=>({ok:r.ok,j:await r.json().catch(()=>({}))}));
async function act(id,a,gb){const r=await pj('/admin/api/user/'+id,{action:a,gb});if(!r.ok)return alert(r.j.error||'Failed');location.reload()}
function addgb(id){const g=prompt('GB to add (negative to remove)','1');if(g&&!isNaN(+g))act(id,'addgb',+g)}
async function credit(id){if(!confirm('Mark as paid and add the storage?'))return;const r=await pj('/admin/api/pay/'+id+'/credit',{});if(!r.ok)return alert('Failed');location.reload()}
document.getElementById('pt').onclick=async()=>{const m=document.getElementById('ptm');m.textContent='Testing…';const r=await pj('/admin/api/pay-test',{});m.textContent=r.j.ok?'✓ API key works':'⚠ '+(r.j.error||('HTTP '+r.j.status))};
document.getElementById('sv').onclick=async()=>{const o={};document.querySelectorAll('[data-k]').forEach(e=>o[e.dataset.k]=e.type==='checkbox'?(e.checked?'1':'0'):e.value);
 const r=await pj('/admin/api/settings',o);document.getElementById('svm').textContent=r.ok?'✓ Saved':'⚠ '+(r.j.error||'Failed');if(r.ok)setTimeout(()=>location.reload(),700)};
</script>{% endraw %}
"""

DEFAULTS = {"free_gb": "1", "p1_gb": "50", "p1_price": "100", "p2_gb": "100", "p2_price": "150", "per_gb": "15",
            "pay_base": "https://techland-stk.vercel.app", "pay_key": "", "pay_whsec": ""}
NUMERIC = ("free_gb", "p1_gb", "p1_price", "p2_gb", "p2_price", "per_gb")
SECRETS = ("pay_key", "pay_whsec")

def settings_all():
    if "s" not in g:
        d = dict(DEFAULTS); d.update({r["key"]: r["value"] for r in q("SELECT key,value FROM settings") if r["key"] in DEFAULTS}); g.s = d
    return g.s

def plans():
    s = settings_all()
    return [{"id": "p1", "gb": int(s["p1_gb"]), "price": int(s["p1_price"])}, {"id": "p2", "gb": int(s["p2_gb"]), "price": int(s["p2_price"])}], int(s["per_gb"])

def log_act(uid, action, detail=""):
    try: q("INSERT INTO activity(user_id,action,detail) VALUES(%s,%s,%s)", (uid, action, str(detail)[:300]))
    except Exception: pass

def mail(to, subject, body):
    try:
        m = EmailMessage(); m["From"] = os.environ.get("MAIL_FROM") or os.environ["SMTP_USER"]; m["To"], m["Subject"] = to, subject; m.set_content(body)
        host, port = os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", 587))
        c = smtplib.SMTP_SSL(host, port, context=ssl.create_default_context(), timeout=15) if port == 465 else smtplib.SMTP(host, port, timeout=15)
        with c:
            if port != 465: c.starttls(context=ssl.create_default_context())
            c.login(os.environ["SMTP_USER"], os.environ["SMTP_PASS"]); c.send_message(m)
        return True
    except Exception:
        log_act(None, "email_failed", to); return False

def welcome(email):
    u = q("SELECT id,username,welcomed FROM users WHERE email=%s", (email,), one=True)
    q("UPDATE users SET verified=TRUE, welcomed=TRUE WHERE email=%s", (email,))
    if u and not u["welcomed"]:
        s = settings_all(); pl, per = plans(); log_act(u["id"], "verified", email)
        mail(email, "Welcome to YIM CLOUD STORAGE — your free storage is ready",
             f"Hi {u['username']},\n\nWelcome to YIM CLOUD STORAGE! Your account is verified and you have {s['free_gb']} GB of free storage to start with.\n\n"
             f"Need more space later? Upgrade any time:\n • {pl[0]['gb']} GB for KSh {pl[0]['price']}\n • {pl[1]['gb']} GB for KSh {pl[1]['price']}\n • Or choose your own size at KSh {per} per GB\n\n"
             f"Open your cloud: {base_url()}\n\n— DEVELOPED BY SYMOH TECH")

def pay_call(method, path, body=None, extra=None):
    """Techland STK API: Bearer key, JSON in/out."""
    s = settings_all(); key = s["pay_key"]
    if not key: return 0, {"error": "Payments are not set up yet. Please contact support."}
    h = {"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json", **(extra or {})}
    req = urllib.request.Request(s["pay_base"].rstrip("/") + path, data=json.dumps(body).encode() if body is not None else None, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=25) as r: code, raw = r.status, r.read()
    except urllib.error.HTTPError as e: code, raw = e.code, e.read()
    except Exception: return 0, {"error": "Could not reach the payment service."}
    try: d = json.loads(raw or b"{}")
    except ValueError: d = {}
    return code, d if isinstance(d, dict) else {}

def credit(pid):
    p = q("UPDATE payments SET status='paid', paid_at=now() WHERE id=%s AND status<>'paid' RETURNING user_id,gb,amount,reference", (pid,), one=True)
    if not p: return
    u = q("UPDATE users SET quota_bytes=quota_bytes+%s WHERE id=%s RETURNING email,username,quota_bytes", (p["gb"] * GB, p["user_id"]), one=True)
    log_act(p["user_id"], "payment_paid", f"{p['gb']}GB KSh {p['amount']} {p['reference']}")
    if u: mail(u["email"], "Payment received — storage added", f"Hi {u['username']},\n\nWe received KSh {p['amount']} (ref {p['reference']}). {p['gb']} GB was added to your account — your total storage is now {human(u['quota_bytes'])}.\n\nThank you!\n— YIM CLOUD STORAGE · DEVELOPED BY SYMOH TECH")

def check_payment(p):
    """Ask Techland for the payment (GET /api/v1/payments/:id) and credit/fail accordingly."""
    if not p["checkout_id"]: return
    code, d = pay_call("GET", "/api/v1/payments/" + urllib.parse.quote(p["checkout_id"], safe=""))
    pay = d.get("payment") if code == 200 else None
    if not isinstance(pay, dict): return
    stat = str(pay.get("status", "")).upper()
    if stat == "SUCCESS":
        try: same = pay.get("amount") is None or int(pay["amount"]) == p["amount"]
        except (TypeError, ValueError): same = False
        if not same: log_act(p["user_id"], "payment_mismatch", f"{p['reference']} expected {p['amount']} got {pay.get('amount')}"); return
        credit(p["id"])
    elif stat in ("FAILED", "CANCELLED"):
        q("UPDATE payments SET status='failed', note=%s WHERE id=%s AND status='pending'", (f"{stat}: {pay.get('message', '')}"[:300], p["id"]))

def norm_phone(x):
    d = re.sub(r"\D", "", x or "")
    if d.startswith("0"): d = "254" + d[1:]
    elif d[:1] in ("7", "1"): d = "254" + d
    return d if re.fullmatch(r"254[17]\d{8}", d) else None

@app.route("/api/pay", methods=["POST"])
@login_required
def api_pay():
    j, uid = request.get_json(silent=True) or {}, session["uid"]
    pl, per = plans(); plan = j.get("plan")
    if plan in ("p1", "p2"): pp = next(x for x in pl if x["id"] == plan); gb, amount = pp["gb"], pp["price"]
    elif plan == "custom":
        try: gb = int(j.get("gb"))
        except (TypeError, ValueError): return {"error": "Enter a number of GB."}, 400
        if not 1 <= gb <= 1000: return {"error": "Choose between 1 and 1000 GB."}, 400
        amount = gb * per
    else: return {"error": "Pick a plan first."}, 400
    phone = norm_phone(j.get("phone"))
    if not phone: return {"error": "Enter a valid M-Pesa number, like 0712345678."}, 400
    if q("SELECT count(*) c FROM payments WHERE user_id=%s AND created_at>now()-interval '1 hour'", (uid,), one=True)["c"] >= 6:
        return {"error": "Too many attempts. Try again in a while."}, 429
    ref = "YIM-" + secrets.token_hex(6).upper()
    row = q("INSERT INTO payments(user_id,gb,amount,phone,plan,reference) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id", (uid, gb, amount, phone, plan, ref), one=True)
    code, d = pay_call("POST", "/api/v1/payments", {"phone": phone, "amount": int(amount), "reference": "YIM STORAGE", "external_ref": ref}, {"Idempotency-Key": ref})
    if code not in (200, 201) or not d.get("ok") or not d.get("id"):
        q("UPDATE payments SET status='failed', note=%s WHERE id=%s", (f"HTTP {code} " + json.dumps(d)[:450], row["id"]))
        if code == 401: log_act(None, "payment_api_key_rejected", "Check the API key in Admin")
        msg = {401: "Payments are not set up yet. Please contact support.", 422: "That phone number or amount isn't valid.",
               429: "Too many attempts. Please wait a few minutes and try again."}.get(code) or str(d.get("error") or "Could not start the payment. Please try again.")[:160]
        return {"error": msg}, 502
    q("UPDATE payments SET checkout_id=%s WHERE id=%s", (str(d["id"]), row["id"]))
    log_act(uid, "payment_started", f"{gb}GB KSh {amount}")
    return {"id": row["id"], "amount": amount, "gb": gb}

@app.route("/api/pay/<int:pid>")
@login_required
def pay_poll(pid):
    p = q("SELECT * FROM payments WHERE id=%s AND user_id=%s", (pid, session["uid"]), one=True)
    if not p: abort(404)
    if p["status"] == "pending":
        check_payment(p); p = q("SELECT status,note FROM payments WHERE id=%s", (pid,), one=True)
    return {"status": p["status"], "message": (p.get("note") or "") if p["status"] == "failed" else ""}

@app.route("/api/pay/webhook", methods=["POST"])
def pay_webhook():
    """Techland webhook: X-Techland-Signature = sha256=HMAC(secret, timestamp + '.' + raw_body)."""
    secret, raw = settings_all()["pay_whsec"], request.get_data()
    ts, sig = request.headers.get("X-Techland-Timestamp", ""), request.headers.get("X-Techland-Signature", "")
    try: fresh = abs(time.time() - int(ts)) < 300
    except ValueError: fresh = False
    mac = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + raw, hashlib.sha256).hexdigest() if secret else ""
    if not (secret and fresh and hmac.compare_digest(mac, sig)): abort(403)
    data = (request.get_json(silent=True) or {}).get("data") or {}
    p = q("SELECT * FROM payments WHERE status='pending' AND (checkout_id=%s OR reference=%s) LIMIT 1", (str(data.get("id") or ""), str(data.get("external_ref") or "")), one=True)
    if p: check_payment(p)  # confirmed with the API before any storage is added
    return {"ok": True}

@app.route("/admin")
@admin_required
def admin():
    qs, s = request.args.get("s", "").strip(), settings_all()
    st = q("""SELECT (SELECT count(*) FROM users) users,(SELECT count(*) FROM users WHERE verified) verified,
      (SELECT count(*) FROM users WHERE created_at>now()-interval '7 days') new7,(SELECT count(*) FROM files WHERE ready) files,
      (SELECT COALESCE(sum(size),0) FROM files WHERE ready) bytes,(SELECT COALESCE(sum(amount),0) FROM payments WHERE status='paid') revenue,
      (SELECT count(*) FROM payments WHERE status='pending') pending""", one=True)
    users = q("""SELECT u.id,u.username,u.email,u.verified,u.blocked,u.is_admin,u.quota_bytes,u.created_at,COALESCE(f.s,0) used,COALESCE(f.c,0) n
      FROM users u LEFT JOIN (SELECT user_id,sum(size) s,count(*) c FROM files WHERE ready GROUP BY user_id) f ON f.user_id=u.id
      WHERE (%s='' OR u.username ILIKE %s OR u.email ILIKE %s) ORDER BY u.created_at DESC LIMIT 100""", (qs, f"%{qs}%", f"%{qs}%"))
    pays = q("SELECT p.*,u.username FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.created_at DESC LIMIT 50")
    acts = q("SELECT a.*,u.username FROM activity a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.created_at DESC LIMIT 60")
    return page(ADMIN_TPL, "Admin · YIM CLOUD STORAGE", full=True, st=st, users=users, pays=pays, acts=acts, s=s, qs=qs, hs=human,
                cb=f"{base_url()}/api/pay/webhook")

@app.route("/admin/api/user/<int:uid>", methods=["POST"])
@admin_required
def admin_user(uid):
    j = request.get_json(silent=True) or {}; a = j.get("action")
    if not q("SELECT 1 FROM users WHERE id=%s", (uid,), one=True): abort(404)
    if uid == session["uid"] and a in ("block", "unadmin"): return {"error": "You can't do that to your own account."}, 400
    if a == "addgb":
        try: gb = float(j.get("gb"))
        except (TypeError, ValueError): return {"error": "Bad number."}, 400
        q("UPDATE users SET quota_bytes=GREATEST(quota_bytes+%s,0) WHERE id=%s", (int(gb * GB), uid))
    elif a in ("block", "unblock"): q("UPDATE users SET blocked=%s WHERE id=%s", (a == "block", uid))
    elif a in ("admin", "unadmin"): q("UPDATE users SET is_admin=%s WHERE id=%s", (a == "admin", uid))
    else: abort(400)
    log_act(session["uid"], "admin_" + a, f"user {uid} {j.get('gb', '')}"); return {"ok": True}

@app.route("/admin/api/pay/<int:pid>/credit", methods=["POST"])
@admin_required
def admin_credit(pid):
    credit(pid); log_act(session["uid"], "admin_credit", f"payment {pid}"); return {"ok": True}

@app.route("/admin/api/settings", methods=["POST"])
@admin_required
def admin_settings():
    j = request.get_json(silent=True) or {}
    for k, v in j.items():
        if k not in DEFAULTS: continue
        v = str(v).strip()
        if k in SECRETS and not v: continue
        if k in NUMERIC and not re.fullmatch(r"\d+(\.\d+)?", v): return {"error": f"{k} must be a number."}, 400
        q("INSERT INTO settings(key,value) VALUES(%s,%s) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value", (k, v))
    log_act(session["uid"], "admin_settings", ",".join(k for k in j if k not in SECRETS)); return {"ok": True}

@app.route("/admin/api/pay-test", methods=["POST"])
@admin_required
def admin_pay_test():
    code, d = pay_call("GET", "/api/v1/payments?limit=1")
    return {"ok": code == 200 and d.get("ok") is not False, "status": code, "error": d.get("error")}
