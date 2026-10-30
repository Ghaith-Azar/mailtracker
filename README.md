# MailTracker

Self-hosted "was my email opened?" tracker with a Gmail extension that adds the
tracking pixel to every email automatically. Server is a single file, no dependencies.

## 1. Server (deploy on Render, free tier)
Files: `app.py`, `requirements.txt`, `render.yaml`. Push them to GitHub, then on
Render: New -> Blueprint -> pick the repo. Set `ADMIN_PASSWORD` and `BASE_URL`
(your https://xxx.onrender.com address, no trailing slash).

Run locally: `ADMIN_PASSWORD=pw python3 app.py` then open http://localhost:8000

Free tier: history is wiped on restart and the service sleeps when idle.

## 2. Gmail extension (Chrome / Edge / Brave)
1. Unzip `mailtracker-extension.zip` to a folder you will keep.
2. Go to `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, choose the folder.
3. The settings page opens (or click Details -> Extension options). Enter your Render URL and
   ADMIN_PASSWORD, click **Save and test**, and allow the permission prompt.
4. Reload Gmail. Compose as usual: a pixel is added automatically and the email appears on your
   dashboard when you press Send.

Notes:
- Only works in Gmail on desktop Chrome-family browsers, not the phone app.
- A pixel is requested when a compose window opens; unsent drafts never show on the dashboard.
- The first compose after the free server has slept may wait up to ~30 s for the pixel.
- Replies and forwards are tracked too.

## Reading the status
- READ: an open that looked human (this includes Gmail's own image proxy, which only loads
  when the message is opened).
- OPENED?: only security-scanner/bot loads were seen.
- NOT READ: nothing loaded. Many people block images, so this is not proof of unread.
- Apple Mail Privacy Protection pre-loads images, so Apple recipients can show false opens.
- Your own opens are ignored for 30 s after sending, and via "Ignore my own opens" on the dashboard.

## Privacy
Tracking recipients may require disclosure/consent in some places (e.g. GDPR).
