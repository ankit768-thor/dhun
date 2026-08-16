#!/usr/bin/env python3
"""Pull Ankit's Spotify listening data and write docs/songs.json for the Dhun site.

First run opens a browser once to authorize (PKCE, no client secret needed).
After that it runs unattended: refresh token -> fetch -> write -> git push.

Usage:
    python3 refresh.py            # fetch, write, commit + push if a remote exists
    python3 refresh.py --no-push  # fetch and write only
    python3 refresh.py --login    # force re-authorization in the browser
"""

import base64
import collections
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, "data")
DOCS = os.path.join(ROOT, "docs")
CONFIG_PATH = os.path.join(DATA, "config.json")
TOKEN_PATH = os.path.join(DATA, "token.json")
OUT_PATH = os.path.join(DOCS, "songs.json")
LOG_PATH = os.path.join(ROOT, "refresh.log")

REDIRECT_PORT = 8788
REDIRECT_URI = f"http://127.0.0.1:{REDIRECT_PORT}/callback"
SCOPES = "user-top-read user-read-recently-played user-read-private"
API = "https://api.spotify.com/v1"
RANGES = ["short_term", "medium_term", "long_term"]


def log(msg):
    line = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_PATH, "a") as fh:
            fh.write(line + "\n")
    except OSError:
        pass


class DhunError(Exception):
    pass


# ---------------------------------------------------------------- config/token

def load_config():
    if not os.path.exists(CONFIG_PATH):
        raise DhunError(
            "Missing data/config.json.\n\n"
            "Create a free Spotify app at https://developer.spotify.com/dashboard\n"
            f"with redirect URI:  {REDIRECT_URI}\n"
            "then save its Client ID as:\n"
            '    {"client_id": "your-client-id-here"}\n'
            f"at {CONFIG_PATH}"
        )
    with open(CONFIG_PATH) as fh:
        cfg = json.load(fh)
    if not cfg.get("client_id"):
        raise DhunError("data/config.json has no client_id")
    return cfg


def read_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH) as fh:
            return json.load(fh)
    return {}


def write_token(tok):
    os.makedirs(DATA, exist_ok=True)
    with open(TOKEN_PATH, "w") as fh:
        json.dump(tok, fh, indent=2)
    os.chmod(TOKEN_PATH, 0o600)


def post_form(url, fields):
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:500]
        raise DhunError(f"Spotify token request failed ({exc.code}): {detail}")


# ------------------------------------------------------------------- auth flow

class _CallbackHandler(BaseHTTPRequestHandler):
    result = {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        _CallbackHandler.result = dict(urllib.parse.parse_qsl(parsed.query))
        ok = "code" in _CallbackHandler.result
        msg = "धुन is connected — you can close this tab." if ok else "Authorization failed."
        page = (
            "<html><head><meta charset='utf-8'><title>dhun</title></head>"
            "<body style=\"background:#0a0a14;color:#f0e6d2;font-family:-apple-system,"
            "system-ui,sans-serif;display:flex;align-items:center;justify-content:center;"
            "height:100vh;margin:0\"><div style='text-align:center'>"
            "<div style='font-size:48px;margin-bottom:12px'>धुन</div>"
            f"<div style='opacity:.75'>{msg}</div></div></body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(page.encode())

    def log_message(self, *args):
        pass


def authorize(client_id):
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).decode().rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .decode()
        .rstrip("=")
    )
    state = secrets.token_urlsafe(16)
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "code_challenge_method": "S256",
        "code_challenge": challenge,
        "state": state,
    }
    url = "https://accounts.spotify.com/authorize?" + urllib.parse.urlencode(params)

    _CallbackHandler.result = {}
    try:
        server = HTTPServer(("127.0.0.1", REDIRECT_PORT), _CallbackHandler)
    except OSError as exc:
        raise DhunError(f"Cannot listen on port {REDIRECT_PORT}: {exc}")
    server.timeout = 180

    log("Opening Spotify authorization in your browser...")
    print(f"\nIf it does not open, paste this into your browser:\n{url}\n")
    webbrowser.open(url)

    deadline = time.time() + 180
    while not _CallbackHandler.result and time.time() < deadline:
        server.handle_request()
    server.server_close()

    res = _CallbackHandler.result
    if "code" not in res:
        raise DhunError(f"Authorization did not complete: {res.get('error', 'timed out')}")
    if res.get("state") != state:
        raise DhunError("State mismatch — authorization rejected for safety.")

    tok = post_form(
        "https://accounts.spotify.com/api/token",
        {
            "grant_type": "authorization_code",
            "code": res["code"],
            "redirect_uri": REDIRECT_URI,
            "client_id": client_id,
            "code_verifier": verifier,
        },
    )
    tok["obtained_at"] = int(time.time())
    write_token(tok)
    log("Authorized. Refresh token saved locally (never published).")
    return tok


def get_access_token(client_id, force_login=False):
    tok = {} if force_login else read_token()
    if not tok.get("refresh_token"):
        tok = authorize(client_id)
        return tok["access_token"]

    fresh = post_form(
        "https://accounts.spotify.com/api/token",
        {
            "grant_type": "refresh_token",
            "refresh_token": tok["refresh_token"],
            "client_id": client_id,
        },
    )
    # Spotify may or may not rotate the refresh token; keep the old one if absent.
    fresh.setdefault("refresh_token", tok["refresh_token"])
    fresh["obtained_at"] = int(time.time())
    write_token(fresh)
    return fresh["access_token"]


# ----------------------------------------------------------------- api helpers

def api_get(path, token, **params):
    url = f"{API}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    for attempt in range(4):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = int(exc.headers.get("Retry-After", "3")) + 1
                log(f"Rate limited, waiting {wait}s...")
                time.sleep(wait)
                continue
            if exc.code >= 500 and attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            detail = exc.read().decode("utf-8", "replace")[:300]
            raise DhunError(f"Spotify API {path} failed ({exc.code}): {detail}")
        except urllib.error.URLError as exc:
            if attempt < 3:
                time.sleep(2 * (attempt + 1))
                continue
            raise DhunError(f"Network error calling {path}: {exc}")
    raise DhunError(f"Gave up calling {path}")


def pick_image(images, prefer=640):
    """Return the URL of the image closest to `prefer` px wide."""
    if not images:
        return None
    best = min(images, key=lambda im: abs((im.get("width") or 0) - prefer))
    return best.get("url")


def slim_track(item, rank=None):
    album = item.get("album") or {}
    out = {
        "id": item.get("id"),
        "name": item.get("name"),
        "artists": [a["name"] for a in item.get("artists", [])],
        "album": album.get("name"),
        "art": pick_image(album.get("images") or []),
        "art_small": pick_image(album.get("images") or [], prefer=160),
        "url": (item.get("external_urls") or {}).get("spotify"),
        "duration_ms": item.get("duration_ms"),
        "popularity": item.get("popularity"),
    }
    if rank is not None:
        out["rank"] = rank
    return out


def slim_artist(item, rank=None):
    out = {
        "id": item.get("id"),
        "name": item.get("name"),
        "genres": item.get("genres", []),
        "image": pick_image(item.get("images") or [], prefer=320),
        "url": (item.get("external_urls") or {}).get("spotify"),
        "popularity": item.get("popularity"),
    }
    if rank is not None:
        out["rank"] = rank
    return out


# --------------------------------------------------------------------- payload

def build_payload(token):
    me = api_get("/me", token)
    log(f"Connected as {me.get('display_name') or me.get('id')}")

    tracks, artists = {}, {}
    for rng in RANGES:
        t = api_get("/me/top/tracks", token, limit=50, time_range=rng)
        tracks[rng] = [slim_track(it, i + 1) for i, it in enumerate(t.get("items", []))]
        log(f"top tracks / {rng}: {len(tracks[rng])}")

        a = api_get("/me/top/artists", token, limit=50, time_range=rng)
        artists[rng] = [slim_artist(it, i + 1) for i, it in enumerate(a.get("items", []))]
        log(f"top artists / {rng}: {len(artists[rng])}")

    recent_raw = api_get("/me/player/recently-played", token, limit=50).get("items", [])
    recent = []
    for it in recent_raw:
        tr = it.get("track") or {}
        if not tr.get("id"):
            continue
        entry = slim_track(tr)
        entry["played_at"] = it.get("played_at")
        recent.append(entry)
    log(f"recently played: {len(recent)}")

    # --- derived stats -------------------------------------------------------
    genre_counts = collections.Counter()
    for rank_i, art in enumerate(artists["medium_term"]):
        weight = max(1, 20 - rank_i)          # higher-ranked artists count more
        for g in art["genres"]:
            genre_counts[g] += weight
    top_genres = [{"name": g, "score": c} for g, c in genre_counts.most_common(8)]

    play_counts = collections.Counter(t["id"] for t in recent)
    obsession = None
    if play_counts:
        best_id, plays = play_counts.most_common(1)[0]
        base = next((t for t in recent if t["id"] == best_id), None)
        if base:
            obsession = dict(base)
            obsession["plays"] = plays

    artist_counts = collections.Counter()
    for t in recent:
        for name in t["artists"]:
            artist_counts[name] += 1
    artist_of_moment = None
    if artist_counts:
        name, plays = artist_counts.most_common(1)[0]
        match = next(
            (a for a in artists["short_term"] + artists["medium_term"] if a["name"] == name),
            None,
        )
        artist_of_moment = {
            "name": name,
            "plays": plays,
            "image": (match or {}).get("image"),
            "url": (match or {}).get("url"),
        }

    recent_minutes = round(sum((t.get("duration_ms") or 0) for t in recent) / 60000)

    now = datetime.now().astimezone()
    return {
        "generated_at": now.isoformat(timespec="seconds"),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "profile": {
            "name": me.get("display_name") or me.get("id"),
            "image": pick_image(me.get("images") or [], prefer=300),
            "url": (me.get("external_urls") or {}).get("spotify"),
        },
        "tracks": tracks,
        "artists": artists,
        "recent": recent,
        "stats": {
            "top_genres": top_genres,
            "obsession": obsession,
            "artist_of_moment": artist_of_moment,
            "recent_minutes": recent_minutes,
            "recent_unique_tracks": len(play_counts),
        },
    }


# ------------------------------------------------------------------------- git

def git(*args):
    return subprocess.run(
        ["git", "-C", ROOT, *args], capture_output=True, text=True, timeout=120
    )


def publish():
    remote = git("remote").stdout.strip()
    if not remote:
        log("No git remote yet — wrote songs.json locally, skipping push.")
        return
    if not git("status", "--porcelain", "docs/songs.json").stdout.strip():
        log("songs.json unchanged — nothing to push.")
        return
    git("add", "docs/songs.json")
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    commit = git("commit", "-m", f"refresh listening data — {stamp}")
    if commit.returncode != 0 and "nothing to commit" not in commit.stdout:
        log(f"Commit failed: {commit.stdout.strip()} {commit.stderr.strip()}")
        return
    push = git("push")
    if push.returncode != 0:
        log(f"Push failed: {push.stderr.strip()}")
        return
    log("Pushed to GitHub — the live site will update in about a minute.")


# ------------------------------------------------------------------------ main

def main():
    args = set(sys.argv[1:])
    try:
        cfg = load_config()
        token = get_access_token(cfg["client_id"], force_login="--login" in args)
        payload = build_payload(token)
        os.makedirs(DOCS, exist_ok=True)
        tmp = OUT_PATH + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, OUT_PATH)
        size_kb = os.path.getsize(OUT_PATH) / 1024
        log(f"Wrote docs/songs.json ({size_kb:.0f} KB)")
        if "--no-push" not in args:
            publish()
        log("Done.")
    except DhunError as exc:
        log(f"ERROR: {exc}")
        return 1
    except Exception as exc:  # noqa: BLE001 - launchd needs a readable log
        log(f"UNEXPECTED ERROR: {type(exc).__name__}: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
