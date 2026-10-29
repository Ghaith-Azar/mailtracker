#!/usr/bin/env python3
"""
MailTracker - a tiny self-hosted "was my email opened?" system.
No third-party dependencies (Python 3.9+).

How it works:
  1. You create a tracked email on the dashboard (recipient + subject).
  2. It gives you a 1x1 invisible image URL / HTML snippet.
  3. Paste the snippet at the bottom of your email.
  4. When the recipient's mail app loads images, this server logs the open.

Env vars:
  ADMIN_PASSWORD  dashboard password (required for any real use)
  BASE_URL        public URL of this server, e.g. https://track.example.com
  PORT            default 8000
  DB_PATH         default tracker.db
  TZ_NAME         default Asia/Amman
"""
import base64
import html
import os
import secrets
import sqlite3
import time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "tracker.db")
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Asia/Amman"))
SELF_OPEN_GRACE_SECONDS = 15  # opens this soon after creation are ignored (your own preview)

# Mail-provider image proxies / scanners: they fetch images automatically,
# so an "open" from them does not prove a human read the message.
PROXY_MARKERS = ("googleimageproxy", "yahoomailproxy", "outlook-ios", "proofpoint",
                 "mimecast", "barracuda", "bot", "scanner", "preview")

GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS emails(
            id TEXT PRIMARY KEY, recipient TEXT, subject TEXT, created_at REAL);
        CREATE TABLE IF NOT EXISTS opens(
            id INTEGER PRIMARY KEY AUTOINCREMENT, email_id TEXT,
            opened_at REAL, ip TEXT, user_agent TEXT, automated INTEGER);
        """)


def fmt(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S") if ts else "—"


def status_of(email_id, conn):
    rows = conn.execute("SELECT * FROM opens WHERE email_id=? ORDER BY opened_at", (email_id,)).fetchall()
    human = [r for r in rows if not r["automated"]]
    if human:
        return "READ", len(human), human[0]["opened_at"], human[-1]["opened_at"]
    if rows:
        return "OPENED?", len(rows), rows[0]["opened_at"], rows[-1]["opened_at"]
    return "NOT READ", 0, None, None


STYLE = """
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:900px;margin:24px auto;padding:0 16px;color:#1a1a1a}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left;font-size:14px}
.badge{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.READ{background:#d4f5dc;color:#116b2b}.NOT{background:#eee;color:#555}.OPENED{background:#fff2cc;color:#8a6100}
input,button{padding:8px;font-size:14px}input{width:100%;box-sizing:border-box;margin:4px 0}
button{cursor:pointer}code,textarea{width:100%;box-sizing:border-box;font-size:12px}
.card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0}
small{color:#666}
</style>"""


def badge(s):
    cls = s.split()[0].rstrip("?")
    return f'<span class="badge {cls}">{html.escape(s)}</span>'


def page_dashboard():
    with db() as c:
        emails = c.execute("SELECT * FROM emails ORDER BY created_at DESC").fetchall()
        rows = ""
        for e in emails:
            s, n, first, last = status_of(e["id"], c)
            rows += (f'<tr><td><a href="/email/{e["id"]}">{html.escape(e["subject"] or "(no subject)")}</a></td>'
                     f'<td>{html.escape(e["recipient"] or "")}</td><td>{badge(s)}</td>'
                     f'<td>{n}</td><td>{fmt(first)}</td><td>{fmt(last)}</td></tr>')
    return f"""<!doctype html><title>MailTracker</title>{STYLE}
<h2>📬 MailTracker</h2>
<div class=card><form method=post action=/create>
<b>Track a new email</b>
<input name=recipient placeholder="Recipient email" required>
<input name=subject placeholder="Subject" required>
<button>Create tracking pixel</button></form>
<small><a href="/ignore-me">Ignore my own opens in this browser</a></small></div>
<table><tr><th>Subject</th><th>To</th><th>Status</th><th>Opens</th><th>First opened</th><th>Last opened</th></tr>
{rows or '<tr><td colspan=6>No tracked emails yet.</td></tr>'}</table>
<p><small>OPENED? = only automated/proxy loads seen, so a human read is not confirmed.</small></p>"""


def page_email(email_id):
    with db() as c:
        e = c.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
        if not e:
            return None
        s, n, first, last = status_of(email_id, c)
        opens = c.execute("SELECT * FROM opens WHERE email_id=? ORDER BY opened_at DESC", (email_id,)).fetchall()
    url = f"{BASE_URL}/t/{email_id}.gif"
    snippet = f'<img src="{url}" width="1" height="1" alt="" style="display:none">'
    log = "".join(
        f'<tr><td>{fmt(o["opened_at"])}</td><td>{"automated/proxy" if o["automated"] else "likely human"}</td>'
        f'<td>{html.escape(o["ip"] or "")}</td><td><small>{html.escape((o["user_agent"] or "")[:90])}</small></td></tr>'
        for o in opens)
    return f"""<!doctype html><title>Email</title>{STYLE}
<p><a href="/">← Back</a></p>
<h3>{html.escape(e["subject"] or "")}</h3>
<p>To: {html.escape(e["recipient"] or "")} &nbsp; {badge(s)} &nbsp; Opens: {n}</p>
<div class=card><b>Paste this at the bottom of your email (HTML mode):</b>
<textarea rows=3 readonly onclick="this.select()">{html.escape(snippet)}</textarea>
<small>Or insert an image from URL: {html.escape(url)}</small></div>
<table><tr><th>Time</th><th>Type</th><th>IP</th><th>Client</th></tr>
{log or '<tr><td colspan=4>No opens yet.</td></tr>'}</table>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    # ---- helpers
    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def authed(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Basic "):
            try:
                _, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                return secrets.compare_digest(pw, ADMIN_PASSWORD)
            except Exception:
                return False
        return False

    def need_auth(self):
        self.send(401, "Login required", headers={"WWW-Authenticate": 'Basic realm="MailTracker"'})

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        return xff.split(",")[0].strip() if xff else self.client_address[0]

    # ---- routes
    def do_GET(self):
        path = urlparse(self.path).path
        if path.startswith("/t/") and path.endswith(".gif"):
            return self.pixel(path[3:-4])
        if not self.authed():
            return self.need_auth()
        if path == "/":
            return self.send(200, page_dashboard())
        if path.startswith("/email/"):
            body = page_email(path.split("/")[2])
            return self.send(200, body) if body else self.send(404, "Not found")
        if path == "/ignore-me":
            return self.send(200, "Your opens in this browser will be ignored. <a href='/'>Back</a>",
                             headers={"Set-Cookie": "mt_me=1; Max-Age=31536000; Path=/; SameSite=Lax"})
        self.send(404, "Not found")

    def do_POST(self):
        if not self.authed():
            return self.need_auth()
        if urlparse(self.path).path != "/create":
            return self.send(404, "Not found")
        length = int(self.headers.get("Content-Length", 0))
        form = parse_qs(self.rfile.read(length).decode())
        eid = secrets.token_urlsafe(12)
        with db() as c:
            c.execute("INSERT INTO emails VALUES(?,?,?,?)", (
                eid, form.get("recipient", [""])[0][:200], form.get("subject", [""])[0][:300], time.time()))
        self.send(303, "", headers={"Location": f"/email/{eid}"})

    def pixel(self, email_id):
        ua = self.headers.get("User-Agent", "")
        jar = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        is_me = "mt_me" in jar
        try:
            with db() as c:
                e = c.execute("SELECT created_at FROM emails WHERE id=?", (email_id,)).fetchone()
                if e and not is_me and time.time() - e["created_at"] > SELF_OPEN_GRACE_SECONDS:
                    automated = int(any(m in ua.lower() for m in PROXY_MARKERS))
                    c.execute("INSERT INTO opens(email_id,opened_at,ip,user_agent,automated) VALUES(?,?,?,?,?)",
                              (email_id, time.time(), self.client_ip(), ua[:300], automated))
        except Exception:
            pass  # never break the image response
        self.send(200, GIF, "image/gif", {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                          "Pragma": "no-cache", "Expires": "0"})


if __name__ == "__main__":
    init_db()
    if ADMIN_PASSWORD == "changeme":
        print("WARNING: set ADMIN_PASSWORD before exposing this server.")
    print(f"MailTracker running on port {PORT}  (dashboard user: any, password: ADMIN_PASSWORD)")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
