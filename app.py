#!/usr/bin/env python3
"""
MailTracker - a small self-hosted "was my email opened?" system.

Storage:
  * TURSO_DATABASE_URL set -> permanent Turso database (free). Recommended.
  * DATABASE_URL set  -> permanent PostgreSQL database (e.g. free Neon).
  * DATABASE_URL unset -> local SQLite file (fine on your own PC; on free Render it is
    wiped every time the server restarts or sleeps).

Env vars:
  ADMIN_PASSWORD  dashboard password
  TURSO_DATABASE_URL + TURSO_AUTH_TOKEN   permanent storage on Turso (recommended)
  DATABASE_URL    or a PostgreSQL connection string (e.g. Neon)
  BASE_URL        public URL (optional; detected automatically from the request)
  PORT            default 8000
  DB_PATH         SQLite file, default tracker.db
  TZ_NAME         default Asia/Amman
"""
import base64
import html
import ipaddress
import json
import os
import secrets
import sqlite3
import sys
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, quote, urlparse
from zoneinfo import ZoneInfo

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:8000").rstrip("/")
PORT = int(os.environ.get("PORT", "8000"))
DB_PATH = os.environ.get("DB_PATH", "tracker.db")
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
TURSO_URL = (os.environ.get("TURSO_DATABASE_URL", "").strip().replace("libsql://", "https://", 1)
             .rstrip("/"))
if TURSO_URL.endswith("/v2/pipeline"):
    TURSO_URL = TURSO_URL[: -len("/v2/pipeline")]
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN", "").strip()
GEO_URL = os.environ.get("GEO_URL", "https://ipwho.is/{ip}")  # free, no key, HTTPS
GEO_CACHE = {}  # ip -> (expires_at, result)
TZ = ZoneInfo(os.environ.get("TZ_NAME", "Asia/Amman"))
EARLY_OPEN_SECONDS = int(os.environ.get("EARLY_OPEN_SECONDS", "35"))  # faster than this = scanner, not a person
SELF_VIEW_WINDOW = 20  # seconds around your own view of a sent message that are treated as you

STARTED = time.time()
PING = {"ts": 0.0, "ua": "", "path": "", "method": ""}  # last keep-alive ping from an uptime monitor
HEALTH_PATHS = ("/health", "/healthz", "/ping", "/status")
MONITOR_UAS = ("uptimerobot", "pingdom", "statuscake", "cron-job.org", "betteruptime", "better stack",
               "freshping", "hetrixtools", "site24x7", "uptime-kuma", "updown.io", "nodeping", "checkly")

# Security scanners / bots that pre-fetch images. Gmail's and Yahoo's image proxies are
# deliberately NOT listed: they only fetch the image when the message is opened.
PROXY_MARKERS = ("proofpoint", "mimecast", "barracuda", "bot", "scanner", "preview", "whatsapp",
                 "facebookexternalhit", "slurp", "crawler", "spider")
HTTP_CLIENT_MARKERS = ("python", "curl/", "wget", "go-http-client", "java/", "apache-httpclient", "axios",
                       "node-fetch", "libwww", "headlesschrome", "phantomjs", "lighthouse", "aiohttp")
SECURITY_NETWORKS = ("proofpoint", "mimecast", "barracuda", "cisco", "ironport", "symantec", "broadcom",
                     "trend micro", "trendmicro", "sophos", "trellix", "fireeye", "forcepoint", "zscaler",
                     "mcafee", "messagelabs", "fortinet", "sonicwall", "cloudmark", "vade", "hornetsecurity",
                     "retarus", "kaspersky", "avanan", "darktrace", "ironscales", "egress")
HOSTING_NETWORKS = ("amazon", "digitalocean", "ovh", "hetzner", "linode", "vultr", "choopa", "leaseweb",
                    "oracle", "alibaba", "scaleway", "contabo", "m247")

GIF = base64.b64decode("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7")


# ----------------------------------------------------------------------------- storage
class TursoCursor:
    def __init__(self, names, rows):
        self._rows = [dict(zip(names, r)) for r in rows]
        self._i = 0

    def fetchone(self):
        if self._i < len(self._rows):
            self._i += 1
            return self._rows[self._i - 1]
        return None

    def fetchall(self):
        out, self._i = self._rows[self._i:], len(self._rows)
        return out

    def __iter__(self):
        return iter(self.fetchall())


def _turso_arg(v):
    if v is None:
        return {"type": "null"}
    if isinstance(v, bool):
        return {"type": "integer", "value": str(int(v))}
    if isinstance(v, int):
        return {"type": "integer", "value": str(v)}
    if isinstance(v, float):
        return {"type": "float", "value": v}
    return {"type": "text", "value": str(v)}


def _turso_val(cell):
    t, v = cell.get("type"), cell.get("value")
    if t == "null":
        return None
    if t == "integer":
        return int(v)
    if t == "float":
        return float(v)
    return v  # text (blobs are not used)


def turso_execute(sql, params=()):
    """Run one statement against Turso over its HTTP API (no extra libraries needed)."""
    body = {"requests": [
        {"type": "execute", "stmt": {"sql": sql, "args": [_turso_arg(p) for p in params]}},
        {"type": "close"}]}
    req = urllib.request.Request(
        TURSO_URL + "/v2/pipeline", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + TURSO_TOKEN, "Content-Type": "application/json",
                 "User-Agent": "MailTracker/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Turso HTTP {e.code}: {e.read()[:300]!r}") from None
    res = data["results"][0]
    if res.get("type") == "error":
        raise RuntimeError("Turso error: " + str(res.get("error", {}).get("message", res)))
    result = res["response"]["result"]
    names = [c["name"] for c in result.get("cols", [])]
    return TursoCursor(names, [[_turso_val(x) for x in row] for row in result.get("rows", [])])


class DB:
    """Tiny wrapper so the same SQL ('?' placeholders) runs on SQLite, Turso and PostgreSQL."""

    def __init__(self):
        self.kind = "turso" if TURSO_URL else ("pg" if DATABASE_URL else "sqlite")
        self.pg = self.kind == "pg"
        self.persistent = self.kind != "sqlite"
        if self.pg:
            import psycopg
            from psycopg.rows import dict_row
            self.c = psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=20)
        elif self.kind == "sqlite":
            self.c = sqlite3.connect(DB_PATH)
            self.c.row_factory = sqlite3.Row

    def execute(self, sql, params=()):
        if self.kind == "turso":
            return turso_execute(sql, params)
        if self.pg:
            sql = sql.replace("?", "%s")
        return self.c.execute(sql, params)

    def __enter__(self):
        return self

    def __exit__(self, et, ev, tb):
        if self.kind == "turso":  # every statement is already committed
            return False
        try:
            self.c.rollback() if et else self.c.commit()
        finally:
            self.c.close()
        return False


def db():
    return DB()


def init_db():
    with db() as c:
        idcol = "BIGSERIAL PRIMARY KEY" if c.pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
        c.execute("""CREATE TABLE IF NOT EXISTS emails(
            id TEXT PRIMARY KEY, recipient TEXT, subject TEXT,
            created_at DOUBLE PRECISION, sent_at DOUBLE PRECISION, pixel_present INTEGER,
            self_view_at DOUBLE PRECISION, sender TEXT)""")
        c.execute(f"""CREATE TABLE IF NOT EXISTS opens(
            id {idcol}, email_id TEXT, opened_at DOUBLE PRECISION,
            ip TEXT, user_agent TEXT, automated INTEGER,
            country TEXT, country_code TEXT, region TEXT, city TEXT, isp TEXT, reason TEXT)""")
        c.execute(f"""CREATE TABLE IF NOT EXISTS hits(
            id {idcol}, ts DOUBLE PRECISION, email_id TEXT, ip TEXT, user_agent TEXT, result TEXT)""")
        c.execute("CREATE INDEX IF NOT EXISTS opens_email ON opens(email_id)")
        c.execute("CREATE INDEX IF NOT EXISTS hits_email ON hits(email_id)")
        # Upgrade databases created by older versions.
        for table, col, typ in (("emails", "sent_at", "DOUBLE PRECISION"), ("emails", "pixel_present", "INTEGER"),
                                ("opens", "country", "TEXT"), ("opens", "country_code", "TEXT"),
                                ("opens", "region", "TEXT"), ("opens", "city", "TEXT"), ("opens", "isp", "TEXT"),
                                ("opens", "reason", "TEXT"), ("emails", "self_view_at", "DOUBLE PRECISION"),
                                ("emails", "sender", "TEXT")):
            if c.pg:
                c.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {typ}")
            else:
                try:
                    c.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
                except Exception as e:
                    if "duplicate column" not in str(e).lower():
                        raise
        # Forget compose windows that were opened but never sent (older than a week).
        c.execute("""DELETE FROM emails WHERE sent_at IS NULL AND created_at < ?
                     AND id NOT IN (SELECT email_id FROM opens)""", (time.time() - 7 * 86400,))


# ----------------------------------------------------------------------------- helpers
def fmt(ts):
    return datetime.fromtimestamp(ts, TZ).strftime("%Y-%m-%d %H:%M:%S") if ts else "—"


def ago(ts):
    s = max(0, int(time.time() - ts))
    if s < 90:
        return f"{s}s ago"
    if s < 5400:
        return f"{s // 60} min ago"
    if s < 172800:
        return f"{s // 3600} h ago"
    return f"{s // 86400} days ago"


def classify_open(ua, isp, delay):
    """Decide whether a load of the tracking image was probably a PERSON reading the email.
    Returns None when it looks human, otherwise a short plain-language reason."""
    u = (ua or "").lower().strip()
    name = parse_client(ua)[0]
    isp_l = (isp or "").lower()
    if not u:
        return "no browser identity (automatic fetch)"
    if any(m in u for m in PROXY_MARKERS):
        return "bot or link-preview fetch"
    if any(m in u for m in HTTP_CLIENT_MARKERS):
        return "automatic program, not a mail app"
    if any(w in isp_l for w in SECURITY_NETWORKS):
        return f"company security scanner ({isp})"
    if name not in ("Gmail", "Yahoo Mail") and any(w in isp_l for w in HOSTING_NETWORKS):
        return f"server in a data center ({isp}), not a person"
    if name == "Apple Mail":
        return "Apple Mail pre-loads images, so this does not prove it was read"
    if delay is not None and delay < EARLY_OPEN_SECONDS:
        return f"arrived {int(max(delay, 0))}s after sending: too fast, servers pre-load on delivery"
    return None


def delay_text(seconds):
    if seconds is None:
        return ""
    seconds = int(max(seconds, 0))
    if seconds < 90:
        return f"{seconds}s after sending"
    if seconds < 5400:
        return f"{seconds // 60} min after sending"
    if seconds < 172800:
        return f"{seconds // 3600} h after sending"
    return f"{seconds // 86400} days after sending"


def status_from(rows):
    human = [r for r in rows if not r["automated"]]
    if human:
        return "READ", len(human), human[0]["opened_at"], human[-1]["opened_at"]
    if rows:
        return "OPENED?", len(rows), rows[0]["opened_at"], rows[-1]["opened_at"]
    return "NOT READ", 0, None, None


def parse_client(ua):
    """Turn a raw User-Agent into (what they read it with, extra detail). Best effort."""
    u = (ua or "").lower()
    if not u:
        return "Unknown", ""
    if "iphone" in u or "ipad" in u:
        os_ = "iPhone/iPad"
    elif "android" in u:
        os_ = "Android"
    elif "windows" in u:
        os_ = "Windows"
    elif "mac os x" in u or "macintosh" in u:
        os_ = "Mac"
    elif "cros" in u:
        os_ = "ChromeOS"
    elif "linux" in u:
        os_ = "Linux"
    else:
        os_ = ""
    if "googleimageproxy" in u or "ggpht.com" in u:
        return "Gmail", "Google hides the real device and browser"
    if "yahoomailproxy" in u or "yahoo" in u:
        return "Yahoo Mail", "Yahoo hides the real device and browser"
    if "microsoft outlook" in u or "microsoft office" in u or "ms-office" in u:
        return "Outlook (desktop app)", os_
    if "thunderbird" in u:
        return "Thunderbird", os_
    if any(m in u for m in PROXY_MARKERS):
        return "Security scanner", "automated, not a person"
    if "edg/" in u or "edge/" in u:
        browser = "Edge"
    elif "opr/" in u or "opera" in u:
        browser = "Opera"
    elif "firefox" in u or "fxios" in u:
        browser = "Firefox"
    elif "crios" in u or ("chrome" in u and "chromium" not in u):
        browser = "Chrome"
    elif "safari" in u and "version/" in u:
        browser = "Safari"
    else:
        browser = ""
    if ("applewebkit" in u and "safari" not in u and "crios" not in u and "fxios" not in u
            and os_ in ("iPhone/iPad", "Mac")):
        return "Apple Mail", os_ + " (Apple may pre-load images, so this can be a false open)"
    if browser:
        return "Web browser / webmail", f"{browser} on {os_}" if os_ else browser
    return "Other", (ua or "")[:60]


def client_label(ua):
    name, detail = parse_client(ua)
    return f"<b>{html.escape(name)}</b>" + (f"<br><small>{html.escape(detail)}</small>" if detail else "")


def geolocate(ip):
    """Approximate location of an IP via a free service. Returns a dict or None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if not addr.is_global:
        return None
    hit = GEO_CACHE.get(ip)
    if hit and hit[0] > time.time():
        return hit[1]
    result, ttl = None, 60  # failures are retried after a minute
    try:
        req = urllib.request.Request(GEO_URL.format(ip=ip), headers={"User-Agent": "MailTracker/1.0"})
        with urllib.request.urlopen(req, timeout=5) as r:
            d = json.load(r)
        if d.get("success", True) and d.get("country"):
            conn = d.get("connection") or {}
            result = {"country": d.get("country"), "country_code": d.get("country_code"),
                      "region": d.get("region"), "city": d.get("city"),
                      "isp": conn.get("isp") or conn.get("org") or d.get("isp")}
            ttl = 86400
    except Exception:
        pass
    if len(GEO_CACHE) > 5000:
        GEO_CACHE.clear()
    GEO_CACHE[ip] = (time.time() + ttl, result)
    return result


PROVIDER_WORDS = ("google", "apple", "microsoft", "yahoo", "cloudflare", "amazon", "proofpoint", "mimecast")


def flag(cc):
    cc = (cc or "").upper()
    return "".join(chr(0x1F1E6 + ord(ch) - 65) for ch in cc) if len(cc) == 2 and cc.isalpha() else ""


def location_label(o):
    """Country/city + IP for one logged open, with a warning when it is a mail provider's server."""
    ip = o["ip"] or ""
    if o["country"]:
        place = ", ".join(x for x in (o["city"], o["region"], o["country"]) if x)
        out = f'{flag(o["country_code"])} {html.escape(place)}'
        isp = o["isp"] or ""
        if isp:
            out += f"<br><small>{html.escape(isp)}</small>"
        proxied = (parse_client(o["user_agent"])[0] in ("Gmail", "Yahoo Mail", "Apple Mail")
                   or any(w in isp.lower() for w in PROVIDER_WORDS))
        if proxied:
            out += "<br><small class=warn>Mail provider's server, not the reader's real location</small>"
    else:
        out = "<small>location unavailable</small>"
    return out + f"<br><small>IP {html.escape(ip)}</small>"


STYLE = """
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
body{font-family:system-ui,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#1a1a1a}
table{width:100%;border-collapse:collapse}td,th{padding:8px;border-bottom:1px solid #ddd;text-align:left;font-size:14px;vertical-align:top}
.badge{padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}
.READ{background:#d4f5dc;color:#116b2b}.NOT{background:#eee;color:#555}.OPENED{background:#fff2cc;color:#8a6100}
input,button{padding:8px;font-size:14px}input{width:100%;box-sizing:border-box;margin:4px 0}
button{cursor:pointer}textarea{width:100%;box-sizing:border-box;font-size:12px}
.card{border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0}
.ok{color:#116b2b}.warn{color:#a15c00;font-weight:600}.bad{color:#b00020;font-weight:600}
small{color:#666}.danger{color:#b00020}
</style>"""


def badge(s):
    cls = s.split()[0].rstrip("?")
    return f'<span class="badge {cls}">{html.escape(s)}</span>'


def health_panel(c, base):
    lines = []
    if c.persistent:
        lines.append('<span class=ok>✅ Storage: permanent database. History survives restarts.</span>')
    else:
        lines.append('<span class=warn>⚠ Storage: temporary file. On free Render all history is wiped when the '
                     'server restarts or sleeps. Connect a free Turso or Neon database to fix this.</span>')
    url = f"{base}/health"
    up_for = time.time() - STARTED
    if PING["ts"] and time.time() - PING["ts"] < 660:
        extra = ""
        if PING["path"].rstrip("/") not in HEALTH_PATHS:
            extra = (f' It is pinging <b>{html.escape(PING["path"])}</b>, which works, but the recommended '
                     f'address is <b>{html.escape(url)}</b>.')
        known = next((m for m in MONITOR_UAS if m in PING["ua"].lower()), None)
        who = {"uptimerobot": "UptimeRobot"}.get(known, known.title() if known else PING["ua"][:45])
        lines.append(f'<span class=ok>✅ Keep-alive working: last ping {ago(PING["ts"])} '
                     f'({html.escape(PING["method"])} {html.escape(PING["path"])} from '
                     f'{html.escape(who)}).</span>{extra}')
    elif PING["ts"]:
        lines.append(f'<span class=warn>⚠ Keep-alive: the last ping was {ago(PING["ts"])}. Your monitor is paused, '
                     'or its interval is longer than 10 minutes. Set it to 5 minutes and make sure it is not paused.</span>')
    elif up_for < 330:
        lines.append(f'<span class=warn>⏳ Keep-alive: waiting for the first ping. The server started {ago(STARTED)} and the '
                     'monitor checks every 5 minutes, so reload this page in a few minutes.</span>')
    else:
        lines.append(f'<span class=warn>⚠ Keep-alive: no ping received since the server started ({ago(STARTED)}). '
                     f'In UptimeRobot check: type <b>HTTP(s)</b>, URL exactly <b>{html.escape(url)}</b>, interval '
                     '<b>5 minutes</b>, and that the monitor is not paused. '
                     f'Test: open <a href="/health">{html.escape(url)}</a> in your browser, it should show "ok".</span>')
    lines.append(f'<small>Server started {fmt(STARTED)} ({ago(STARTED)}). '
                 f'<a href="/debug">Show every pixel request received</a></small>')
    return '<div class=card>' + "<br>".join(lines) + "</div>"


CONFIRM_JS = ("var n=document.querySelectorAll('input[name=id]:checked').length;"
              "if(!n){alert('Tick at least one email first.');return false}"
              "return confirm('Permanently delete '+n+' email(s) and their open history?')")


VISIBLE = "(sent_at IS NOT NULL)"  # emails still being written (not sent) are never listed


def page_dashboard(base, sender_filter=None):
    with db() as c:
        where, params = VISIBLE, []
        if sender_filter == "__none__":
            where += " AND (sender IS NULL OR sender = '')"
        elif sender_filter:
            where += " AND sender = ?"
            params.append(sender_filter.strip().lower())
        emails = c.execute(f"""SELECT * FROM emails WHERE {where}
                               ORDER BY COALESCE(sent_at, created_at) DESC LIMIT 200""", params).fetchall()
        accounts = c.execute(f"""SELECT COALESCE(sender, '') AS s, COUNT(*) AS n FROM emails
                                 WHERE {VISIBLE} GROUP BY COALESCE(sender, '') ORDER BY n DESC""").fetchall()
        by_email = {}
        if emails:
            ids = [e["id"] for e in emails]
            q = ",".join("?" * len(ids))
            for o in c.execute(f"SELECT * FROM opens WHERE email_id IN ({q}) ORDER BY opened_at", ids):
                by_email.setdefault(o["email_id"], []).append(o)
        panel = health_panel(c, base)
    total = sum(a["n"] for a in accounts)
    chips = [f'<a href="/">{"<b>All</b>" if not sender_filter else "All"} ({total})</a>']
    for a in accounts:
        token = a["s"] or "__none__"
        label = html.escape(a["s"] or "(sender not recorded)")
        shown = f"<b>{label}</b>" if sender_filter and (sender_filter == token or sender_filter.lower() == a["s"]) else label
        chips.append(f'<a href="/?from={quote(token)}">{shown} ({a["n"]})</a>')
    account_bar = '<p class=card><small>Sent from:</small> ' + " &nbsp;·&nbsp; ".join(chips) + "</p>"
    rows = ""
    for e in emails:
        opens = [o for o in by_email.get(e["id"], []) if not e["sent_at"] or o["opened_at"] >= e["sent_at"]]
        s, n, first, last = status_from(opens)
        pick = ([o for o in reversed(opens) if not o["automated"]] or list(reversed(opens)) or [None])[0]
        via = client_label(pick["user_agent"]) if pick else "—"
        where = location_label(pick) if pick else "—"
        warn = "<br><small class=bad>⚠ tracking pixel was missing when sent</small>" if e["pixel_present"] == 0 else ""
        rows += (f'<tr><td><input type=checkbox name=id value="{e["id"]}"></td>'
                 f'<td><a href="/email/{e["id"]}">{html.escape(e["subject"] or "(no subject)")}</a>{warn}</td>'
                 f'<td><small>{html.escape(e["sender"] or "—")}</small></td>'
                 f'<td>{html.escape(e["recipient"] or "")}</td><td>{badge(s)}</td>'
                 f'<td>{n}</td><td>{via}</td><td>{where}</td><td>{fmt(first)}</td><td>{fmt(last)}</td></tr>')
    return f"""<!doctype html><title>MailTracker</title>{STYLE}
<h2>📬 MailTracker</h2>{panel}{account_bar}
<form method=post action=/delete onsubmit="{CONFIRM_JS}">
<p><button class=danger>🗑 Delete selected</button> <small>Tick the boxes (top box selects all).</small></p>
<table><tr><th><input type=checkbox title="Select all" onclick="document.querySelectorAll('input[name=id]').forEach(b=>b.checked=this.checked)"></th>
<th>Subject</th><th>From (your account)</th><th>To</th><th>Status</th><th>Opens</th><th>Opened with</th><th>Location</th><th>First opened</th><th>Last opened</th></tr>
{rows or '<tr><td colspan=10>No tracked emails yet.</td></tr>'}</table></form>
<p><small><b>READ</b> = at least one load that looks like a real person.
<b>OPENED?</b> = the image was loaded, but only in ways that can be automatic (security scanners, Apple Mail pre-loading,
loads within {EARLY_OPEN_SECONDS}s of sending, your own view). Open the email to see the reason for each load.
<a href="/ignore-me">Ignore my own opens in this browser</a></small></p>
<details class=card><summary>Track an email by hand (without the Gmail extension)</summary>
<form method=post action=/create><input name=recipient placeholder="Recipient email" required>
<input name=subject placeholder="Subject" required><button>Create tracking pixel</button></form></details>"""


def page_email(email_id, base):
    with db() as c:
        e = c.execute("SELECT * FROM emails WHERE id=?", (email_id,)).fetchone()
        if not e:
            return None
        opens = c.execute("SELECT * FROM opens WHERE email_id=? ORDER BY opened_at DESC", (email_id,)).fetchall()
        if e["sent_at"]:  # loads before the send moment were you writing the email, not a reader
            opens = [o for o in opens if o["opened_at"] >= e["sent_at"]]
        hits = c.execute("SELECT * FROM hits WHERE email_id=? ORDER BY ts DESC LIMIT 50", (email_id,)).fetchall()
    s, n, first, last = status_from(list(reversed(opens)))
    ref = e["sent_at"] or e["created_at"] or 0
    url = f"{base}/t/{email_id}.gif"
    snippet = f'<img src="{url}" width="1" height="1" alt="" style="display:none">'
    log = "".join(
        f'<tr><td>{fmt(o["opened_at"])}<br><small>{delay_text(o["opened_at"] - ref)}</small></td>'
        f'<td>{("<span class=ok>looks like a person</span>" if not o["automated"] else "<span class=warn>automatic?</span><br><small>" + html.escape(o["reason"] or "flagged as automatic") + "</small>")}</td>'
        f'<td>{client_label(o["user_agent"])}</td><td>{location_label(o)}</td></tr>' for o in opens)
    raw = "".join(
        f'<tr><td>{fmt(h["ts"])}</td><td>{html.escape(h["result"])}</td><td>{client_label(h["user_agent"])}'
        f'<br><small>IP {html.escape(h["ip"] or "")}</small></td></tr>'
        for h in hits)
    warn = "<p class=bad>⚠ The tracking pixel was missing from this email when it was sent.</p>" if e["pixel_present"] == 0 else ""
    return f"""<!doctype html><title>Email</title>{STYLE}
<p><a href="/">← Back</a></p>
<form method=post action=/delete style="float:right" onsubmit="return confirm('Permanently delete this email and its open history?')">
<input type=hidden name=id value="{html.escape(email_id)}"><button class=danger>🗑 Delete this email</button></form>
<h3>{html.escape(e["subject"] or "(no subject)")}</h3>
<p>From: <b>{html.escape(e["sender"] or "not recorded")}</b> &nbsp; To: {html.escape(e["recipient"] or "")} &nbsp; {badge(s)} &nbsp; Opens: {n}</p>{warn}
<table><tr><th>Time</th><th>Verdict</th><th>Opened with</th><th>Location / IP</th></tr>
{log or '<tr><td colspan=4>No opens yet.</td></tr>'}</table>
<h4>Every request the server received for this email's pixel</h4>
<table><tr><th>Time</th><th>What happened</th><th>From</th></tr>
{raw or '<tr><td colspan=3>None. Nothing has requested the image yet, so the email has not been opened (or images are blocked).</td></tr>'}</table>
<div class=card><b>Pixel address</b> (only needed for manual use):
<textarea rows=2 readonly onclick="this.select()">{html.escape(snippet)}</textarea></div>"""


def page_debug(base):
    with db() as c:
        hits = c.execute("SELECT * FROM hits ORDER BY ts DESC LIMIT 60").fetchall()
        panel = health_panel(c, base)
    rows = "".join(
        f'<tr><td>{fmt(h["ts"])}</td><td><small>{html.escape(h["email_id"] or "")}</small></td>'
        f'<td>{html.escape(h["result"])}</td><td>{client_label(h["user_agent"])}</td></tr>' for h in hits)
    return f"""<!doctype html><title>Debug</title>{STYLE}<p><a href="/">← Back</a></p>
<h3>Last pixel requests received</h3>{panel}
<p><small>If an email was opened but nothing appears here, the image never reached this server
(the pixel was removed from the email, images were blocked, or the server was asleep).</small></p>
<table><tr><th>Time</th><th>Email id</th><th>Result</th><th>From</th></tr>
{rows or '<tr><td colspan=4>No pixel requests yet.</td></tr>'}</table>"""


# ----------------------------------------------------------------------------- http
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def send(self, code, body, ctype="text/html; charset=utf-8", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, obj, code=200):
        self.send(code, json.dumps(obj), "application/json")

    def authed(self):
        h = self.headers.get("Authorization", "")
        if h.startswith("Bearer "):  # used by the Gmail extension
            return secrets.compare_digest(h[7:], ADMIN_PASSWORD)
        if h.startswith("Basic "):
            try:
                _, pw = base64.b64decode(h[6:]).decode().split(":", 1)
                return secrets.compare_digest(pw, ADMIN_PASSWORD)
            except Exception:
                return False
        return False

    def need_auth(self):
        self.send(401, "Login required", headers={"WWW-Authenticate": 'Basic realm="MailTracker"'})

    def base_url(self):
        """Public address for tracking pixels: BASE_URL if it is a real address, otherwise
        the address this request actually arrived on."""
        if "localhost" not in BASE_URL and "127.0.0.1" not in BASE_URL:
            return BASE_URL
        host = self.headers.get("X-Forwarded-Host") or self.headers.get("Host") or f"localhost:{PORT}"
        proto = (self.headers.get("X-Forwarded-Proto") or "http").split(",")[0].strip()
        return f"{proto}://{host}"

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For")
        return xff.split(",")[0].strip() if xff else self.client_address[0]

    def is_monitor_request(self, path):
        """A keep-alive ping: the /health address, or any address requested by a known monitoring service
        (so a monitor pointed at the wrong page still keeps the server awake and gets a friendly 'ok')."""
        ua = self.headers.get("User-Agent", "").lower()
        p = path.rstrip("/") or "/"
        return p in HEALTH_PATHS or (any(m in ua for m in MONITOR_UAS) and not p.startswith("/t/"))

    def note_ping(self, path, method):
        ua = self.headers.get("User-Agent", "")
        if "render" in ua.lower():  # Render's own health checks do not keep a free service awake
            return
        PING.update(ts=time.time(), ua=ua, path=path[:80], method=method)

    def do_HEAD(self):
        path = urlparse(self.path).path
        if self.is_monitor_request(path):
            self.note_ping(path, "HEAD")
            self.send_response(200)
        else:
            self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if self.is_monitor_request(path):  # public: uptime monitors
            self.note_ping(path, "GET")
            return self.send(200, "ok", "text/plain")
        if path.startswith("/t/") and path.endswith(".gif"):
            return self.pixel(path[3:-4][:60])
        if not self.authed():
            return self.need_auth()
        if path == "/api/ping":
            return self.send_json({"ok": True})
        if path == "/":
            who = parse_qs(parsed.query).get("from", [None])[0]
            return self.send(200, page_dashboard(self.base_url(), who))
        if path == "/debug":
            return self.send(200, page_debug(self.base_url()))
        if path.startswith("/email/"):
            body = page_email(path.split("/")[2], self.base_url())
            return self.send(200, body) if body else self.send(404, "Not found")
        if path == "/ignore-me":
            return self.send(200, "Your opens in this browser will be ignored. <a href='/'>Back</a>",
                             headers={"Set-Cookie": "mt_me=1; Max-Age=31536000; Path=/; SameSite=Lax"})
        self.send(404, "Not found")

    def same_site(self):
        """Browsers resend saved passwords on cross-site form posts, so only accept deletes
        that really come from a page on this server."""
        src = self.headers.get("Origin") or self.headers.get("Referer") or ""
        hosts = {self.headers.get("Host"), self.headers.get("X-Forwarded-Host")} - {None}
        return bool(src) and urlparse(src).netloc in hosts

    def do_POST(self):
        if not self.authed():
            return self.need_auth()
        path = urlparse(self.path).path
        length = min(int(self.headers.get("Content-Length", 0)), 65536)
        raw = self.rfile.read(length).decode("utf-8", "replace")
        now = time.time()

        if path == "/create":  # manual form
            form = parse_qs(raw)
            eid = secrets.token_urlsafe(12)
            with db() as c:
                c.execute("INSERT INTO emails(id,recipient,subject,created_at,sent_at) VALUES(?,?,?,?,?)", (
                    eid, form.get("recipient", [""])[0][:200], form.get("subject", [""])[0][:300], now, now))
            return self.send(303, "", headers={"Location": f"/email/{eid}"})

        if path == "/delete":
            if not self.same_site():
                return self.send(403, "Blocked: this request did not come from the MailTracker page.")
            ids = [i[:60] for i in parse_qs(raw).get("id", [])][:500]
            if ids:
                q = ",".join("?" * len(ids))
                with db() as c:
                    c.execute(f"DELETE FROM opens WHERE email_id IN ({q})", ids)
                    c.execute(f"DELETE FROM hits WHERE email_id IN ({q})", ids)
                    c.execute(f"DELETE FROM emails WHERE id IN ({q})", ids)
            return self.send(303, "", headers={"Location": "/"})

        if path == "/api/selfview":  # extension: you are looking at your own sent message
            try:
                data = json.loads(raw)
            except ValueError:
                return self.send_json({"error": "bad json"}, 400)
            eid = str(data.get("id", ""))[:60]
            with db() as c:
                c.execute("UPDATE emails SET self_view_at=? WHERE id=?", (now, eid))
                c.execute("""UPDATE opens SET automated=1, reason=?
                             WHERE email_id=? AND opened_at BETWEEN ? AND ? AND automated=0""",
                          ("you were viewing your own sent message at that moment", eid,
                           now - SELF_VIEW_WINDOW, now + SELF_VIEW_WINDOW))
            return self.send_json({"ok": True})

        if path == "/api/new":  # extension: compose window opened -> hand out a pixel
            eid = secrets.token_urlsafe(12)
            with db() as c:
                c.execute("INSERT INTO emails(id,created_at) VALUES(?,?)", (eid, now))
            return self.send_json({"id": eid, "url": f"{self.base_url()}/t/{eid}.gif"})

        if path == "/api/sent":  # extension: Send was pressed
            try:
                data = json.loads(raw)
            except ValueError:
                return self.send_json({"error": "bad json"}, 400)
            present = data.get("pixel_present")
            present = None if present is None else int(bool(present))
            with db() as c:
                c.execute("""UPDATE emails SET recipient=?, subject=?, sent_at=?, pixel_present=?, sender=?
                             WHERE id=? AND sent_at IS NULL""", (
                    str(data.get("recipient", ""))[:200], str(data.get("subject", ""))[:300], now, present,
                    str(data.get("sender", "")).strip().lower()[:200], str(data.get("id", ""))))
            return self.send_json({"ok": True})

        self.send(404, "Not found")

    def pixel(self, email_id):
        ua = self.headers.get("User-Agent", "")
        ip = self.client_ip()
        is_me = "mt_me" in cookies.SimpleCookie(self.headers.get("Cookie", ""))
        # Answer immediately so the recipient's mail app never waits on our database.
        self.send(200, GIF, "image/gif", {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                                          "Pragma": "no-cache", "Expires": "0"})
        try:
            with db() as c:
                now = time.time()
                e = c.execute("""SELECT COALESCE(sent_at, created_at) AS ref, sent_at, self_view_at FROM emails
                                 WHERE id=?""", (email_id,)).fetchone()
                if e and e["sent_at"] is None:
                    result = "ignored: email not sent yet (you are writing it, or the draft is open)"
                elif not e:
                    result = "ignored: unknown id (data was lost in a restart, or wrong link)"
                elif is_me:
                    result = "ignored: from your own browser"
                else:
                    g = geolocate(ip) or {}
                    delay = now - e["ref"]
                    reason = classify_open(ua, g.get("isp"), delay)
                    if (reason is None and e["self_view_at"]
                            and abs(now - e["self_view_at"]) <= SELF_VIEW_WINDOW):
                        reason = "you were viewing your own sent message at that moment"
                    result = "counted as an open" + (f" (flagged automatic: {reason})" if reason else " (looks like a person)")
                    c.execute("""INSERT INTO opens(email_id,opened_at,ip,user_agent,automated,
                                 country,country_code,region,city,isp,reason) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                              (email_id, now, ip, ua[:300], int(reason is not None), g.get("country"),
                               g.get("country_code"), g.get("region"), g.get("city"), g.get("isp"), reason))
                c.execute("INSERT INTO hits(ts,email_id,ip,user_agent,result) VALUES(?,?,?,?,?)",
                          (now, email_id, ip, ua[:300], result))
                c.execute("DELETE FROM hits WHERE id < (SELECT MAX(id) FROM hits) - 500")
        except Exception:
            traceback.print_exc(file=sys.stderr)


if __name__ == "__main__":
    try:
        init_db()
    except Exception as e:
        print(f"\nCANNOT CONNECT TO THE DATABASE: {e}\n"
              "Check TURSO_DATABASE_URL (should start with libsql:// or https://) and TURSO_AUTH_TOKEN "
              "(or DATABASE_URL), with no extra spaces or quotes.", file=sys.stderr)
        sys.exit(1)
    if ADMIN_PASSWORD == "changeme":
        print("WARNING: set ADMIN_PASSWORD before exposing this server.")
    kind = "Turso" if TURSO_URL else ("PostgreSQL" if DATABASE_URL else "SQLite " + DB_PATH)
    print(f"MailTracker on port {PORT}; storage: {kind}")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
