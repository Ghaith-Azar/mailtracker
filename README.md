# MailTracker

A tiny self-hosted system to see whether someone opened an email you sent.
Single file, no dependencies (Python 3.9+).

## Run it
```
ADMIN_PASSWORD=pick-a-strong-one \
BASE_URL=https://track.yourdomain.com \
python3 app.py
```
Open `http://localhost:8000` and log in (any username, your ADMIN_PASSWORD).

## Use it
1. On the dashboard, enter recipient + subject -> **Create tracking pixel**.
2. Copy the `<img ...>` snippet (or the image URL) from the detail page.
3. Put it at the bottom of your email (HTML editor, or "insert image from URL").
4. Watch the status: **NOT READ**, **OPENED?**, or **READ**.

## IMPORTANT: it must be reachable from the internet
The recipient's mail app loads the pixel from `BASE_URL`, so `localhost` only
works for testing. Deploy it to a small VPS / Render / Fly.io / Railway behind
HTTPS and set `BASE_URL` to that public address. Put it behind a reverse proxy
that forwards `X-Forwarded-For` if you want real IPs.

## Limits you should know about
- **Only works if the recipient's client loads images.** Many people block
  them -> shows NOT READ even if they read it.
- **Apple Mail (Privacy Protection) and Gmail's image proxy pre-load images**,
  so some "opens" are not real reads. The app labels proxy-looking hits as
  `OPENED?` rather than `READ`, but detection is best-effort.
- Your own opens are ignored for the first 15 seconds, and you can click
  "Ignore my own opens" on the dashboard to ignore opens from your browser.
- Tracking people may require disclosure/consent in some jurisdictions (e.g. GDPR).

## Files
- `app.py` - server, dashboard and tracking pixel
- `tracker.db` - SQLite data, created on first run

## Config
`ADMIN_PASSWORD`, `BASE_URL`, `PORT` (8000), `DB_PATH` (tracker.db), `TZ_NAME` (Asia/Amman)
