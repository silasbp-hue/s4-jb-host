# PS4 JB Host — Home Assistant add-on
# language: Python 3.12, file: app/ps4jb.py, target: HA OS add-on (host_network)
#
# Serves a locally hosted WebKitty exploit page, optional fake-DNS so the PS4
# "User's Guide" button lands on the host, and a GoldHEN BinLoader injector
# (port 9090) with automatic payload push when the console comes online.

import hashlib
import json
import os
import re
import shutil
import signal
import socket
import struct
import sys
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DATA = Path("/data")
OPTIONS_FILE = DATA / "options.json"
WEBKITTY_DIR = DATA / "webkitty"
STATE_FILE = DATA / "state.json"
GOLDHEN_JSON = DATA / "goldhen.json"
REPO = "https://github.com/ArabPixel/WebKitty.git"
WEBKITTY_TARBALL = "https://codeload.github.com/ArabPixel/WebKitty/tar.gz/refs/heads/main"

# GoldHEN upstream: GamerHack's all-in-one drop, always carries the current build
GOLDHEN_API = "https://api.github.com/repos/GamerHack/GamerHack.github.io/contents/g2all"
GOLDHEN_RAW = "https://raw.githubusercontent.com/GamerHack/GamerHack.github.io/main/g2all/"
GOLDHEN_NAME = re.compile(r"goldhen_(\d+)\.(\d+)b(\d+)\.(\d+)\.bin$", re.I)

BINLOADER_PORT = 9090
FTP_PORT = 2121
KLOG_PORT = 3232

state_lock = threading.Lock()
state = {
    "jailbroken": False,
    "binloader": False,
    "ftp": False,
    "klog": False,
    "last_check": 0,
    "last_inject": None,
    "injected": [],
    "goldhen": {},
}



def log(msg):
    print(f"[ps4jb] {msg}", flush=True)


def load_options():
    defaults = {
        "ps4_host": "",
        "http_port": 8080,
        "landing_path": "/",
        "dns_enabled": False,
        "dns_port": 53,
        "dns_upstream": "1.1.1.1",
        "intercept_domains": ["manuals.playstation.net"],
        "block_domains": [
            "ps4.update.playstation.net",
            "update.playstation.net",
            "post.net.playstation.net",
        ],
        "auto_inject": True,
        "inject_once": True,
        "payload_dir": "/share/ps4jb/auto",
        "goldhen_dir": "/share/ps4jb/payloads",
        "goldhen_auto_update": True,
        "goldhen_check_interval": 3600,
        "github_token": "",
        "github_repo": "silasbp-hue/s4-jb-host",
        "github_branch": "main",
        "github_auto_push": True,
        "poll_interval": 15,
        "entity_prefix": "ps4_jb",
    }
    opts = dict(defaults)
    if OPTIONS_FILE.exists():
        try:
            opts.update(json.loads(OPTIONS_FILE.read_text()))
        except Exception as exc:  # noqa: BLE001
            log(f"options parse failed: {exc}")
    return opts


def lan_ip():
    """Local LAN address, resolved without traffic actually leaving the box."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("1.1.1.1", 53))
        addr = s.getsockname()[0]
        s.close()
        return addr
    except OSError:
        return "127.0.0.1"


def sync_webkitty(force=False):
    """Pull WebKitty as a tarball into /data. No git binary, no build deps —
    the whole fetch is urllib + tarfile, which matters on a 1 GB Pi."""
    if (WEBKITTY_DIR / "index.html").exists() and not force:
        return True
    stamp = time.strftime("%Y%m%d-%H%M%S")
    log(f"fetching WebKitty tarball ({stamp})")
    try:
        with tempfile.TemporaryDirectory() as td:
            tgz = Path(td) / "webkitty.tgz"
            urllib.request.urlretrieve(WEBKITTY_TARBALL, tgz)
            with tarfile.open(tgz) as tar:
                tar.extractall(td, filter="data")
            roots = [p for p in Path(td).iterdir() if p.is_dir()]
            if not roots:
                log("webkitty tarball had no root dir")
                return False
            if WEBKITTY_DIR.exists():
                shutil.rmtree(WEBKITTY_DIR)
            shutil.copytree(roots[0], WEBKITTY_DIR)
        log("webkitty unpacked")
        # Pin WebKitty to the newest GoldHEN we have, removing older versions
        _pin_webkitty_goldhen()
        return (WEBKITTY_DIR / "index.html").exists()
    except (OSError, tarfile.TarError) as exc:
        log(f"webkitty sync failed: {exc}")
        return (WEBKITTY_DIR / "index.html").exists()


def github_push_latest(opts, version=""):
    """Publish the current app.py + config.yaml + README to GitHub via the
    Contents API, one commit per file. Runs only when github_auto_push is on."""
    token = opts.get("github_token", "")
    repo = opts.get("github_repo")
    if not repo or not token:
        return
    branch = opts.get("github_branch", "main")
    base = f"https://api.github.com/repos/{repo}/contents"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "ps4-jb-host",
    }
    for rel in ("app/ps4jb.py", "config.yaml", "README.md"):
        # GitHub keeps app/ps4jb.py, but the container holds a flat /app tree.
        local_name = Path(rel).name
        src = Path("/app") / local_name
        if not src.exists():
            src = Path(local_name)
        if not src.exists():
            continue
        import base64
        content = base64.b64encode(src.read_bytes()).decode()
        # Get existing sha to overwrite
        sha = None
        try:
            r = urllib.request.urlopen(urllib.request.Request(
                f"{base}/{rel}?ref={branch}", headers={"Authorization": f"Bearer {token}", "User-Agent": "ps4-jb-host"}))
            sha = json.loads(r.read()).get("sha")
        except (urllib.error.HTTPError, urllib.error.URLError):
            pass
        body = {"message": f"auto: sync after GoldHEN {version}",
                "content": content, "branch": branch}
        if sha:
            body["sha"] = sha
        req = urllib.request.Request(f"{base}/{rel}", data=json.dumps(body).encode(), headers=headers, method="PUT")
        try:
            urllib.request.urlopen(req, timeout=60).read()
            log(f"github push {rel} ok")
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            log(f"github push {rel} failed: {exc}")
def _pin_webkitty_goldhen():
    """Rewrite HENs.js so WebKitty only offers the newest GoldHEN, and copy
    the freshly downloaded payload over the bundled one."""
    manifest = read_goldhen_manifest()
    version = manifest.get("version")  # e.g. "2.4b18.14"
    if not version:
        return
    hens = WEBKITTY_DIR / "includes" / "js" / "HENs.js"
    if not hens.exists():
        return
    key = f"GHv{version}"
    filename = f"goldhen_v{version}.bin"
    text = hens.read_text()
    # Replace the version map with a single entry for the newest build
    import re
    text = re.sub(
        r"var GOLDHEN_VERSIONS = \{[^}]*\};",
        f"var GOLDHEN_VERSIONS = {{\n    '{key}': '{filename}',\n}};",
        text,
        count=1,
    )
    text = re.sub(
        r"var GOLDHEN_DEFAULT = '[^']*';",
        f"var GOLDHEN_DEFAULT = '{key}';",
        text,
        count=1,
    )
    hens.write_text(text)
    # Copy the freshly downloaded payload over the bundled one
    src = Path(manifest.get("path", ""))
    dst = WEBKITTY_DIR / "includes" / "payloads" / "HEN" / filename
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        log(f"webkitty pinned to {key} ({filename})")


# ------------------------------------------------------- goldhen updater


def _gh_headers(token):
    h = {"User-Agent": "ps4-jb-host/1.1", "Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def parse_goldhen_version(name):
    m = GOLDHEN_NAME.search(name)
    return tuple(int(x) for x in m.groups()) if m else None


def goldhen_remote(token=""):
    """Newest goldhen_<maj>.<maj>b<build>.<rev>.bin in GamerHack/g2all."""
    req = urllib.request.Request(GOLDHEN_API, headers=_gh_headers(token))
    with urllib.request.urlopen(req, timeout=20) as resp:
        listing = json.load(resp)
    best = None
    for f in listing:
        name = f.get("name", "")
        ver = parse_goldhen_version(name)
        if not ver:
            continue
        cand = {
            "version": f"{ver[0]}.{ver[1]}b{ver[2]}.{ver[3]}",
            "name": name,
            "size": f.get("size"),
            "url": f.get("download_url") or (GOLDHEN_RAW + name),
            "_ver": ver,
        }
        if best is None or cand["_ver"] > best["_ver"]:
            best = cand
    return best


def read_goldhen_manifest():
    if GOLDHEN_JSON.exists():
        try:
            return json.loads(GOLDHEN_JSON.read_text())
        except Exception:  # noqa: BLE001
            pass
    return {}


def _download(url, dest: Path, token=""):
    part = dest.with_suffix(dest.suffix + ".part")
    req = urllib.request.Request(url, headers={"User-Agent": "ps4-jb-host/1.1"})
    digest = hashlib.sha256()
    n = 0
    with urllib.request.urlopen(req, timeout=120) as resp, open(part, "wb") as fh:
        while True:
            chunk = resp.read(65536)
            if not chunk:
                break
            fh.write(chunk)
            digest.update(chunk)
            n += len(chunk)
    part.replace(dest)
    return n, digest.hexdigest()


def sync_goldhen(opts, force=False):
    """Fetch the newest GoldHEN payload. Never destructive: a failed check keeps
    the last good file and the old manifest."""
    dest_dir = Path(opts["goldhen_dir"])
    dest_dir.mkdir(parents=True, exist_ok=True)
    token = opts.get("github_token") or ""
    # Fallback: token file (for setups where the Supervisor options dialog is
    # unreachable or protection mode blocks the API)
    if not token:
        for p in (Path("/data/.token"), Path("/app/.token"), Path("/addons/ps4_jb_host/.token"), Path("/config/.token"), Path("/share/ps4jb/.token")):
            try:
                token = p.read_text().strip()
                if token:
                    break
            except OSError:
                pass
    if token:
        opts["github_token"] = token
    manifest = read_goldhen_manifest()

    try:
        remote = goldhen_remote(token)
    except urllib.error.HTTPError as exc:
        log(f"goldhen check: github {exc.code} (rate limit? add github_token)")
        return manifest
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"goldhen check failed: {exc}")
        return manifest
    if not remote:
        log("goldhen check: no matching asset")
        return manifest

    have = manifest.get("version")
    if have == remote["version"] and not force:
        return manifest

    target = dest_dir / remote["name"]
    stable = dest_dir / "goldhen.bin"
    try:
        size, sha = _download(remote["url"], target, token)
    except (urllib.error.URLError, OSError) as exc:
        log(f"goldhen download failed: {exc}")
        return manifest

    shutil.copyfile(target, stable)
    manifest = {
        "version": remote["version"],
        "file": remote["name"],
        "path": str(stable),
        "size": size,
        "sha256": sha,
        "source": remote["url"],
        "fetched_at": time.time(),
    }
    GOLDHEN_JSON.write_text(json.dumps(manifest, indent=2))
    with state_lock:
        state["goldhen"] = manifest
def sync_goldhen(opts, force=False):
    """Fetch the newest GoldHEN payload. Never destructive: a failed check keeps
    the last good file and the old manifest."""
    dest_dir = Path(opts["goldhen_dir"])
    dest_dir.mkdir(parents=True, exist_ok=True)
    token = opts.get("github_token") or ""
    # Fallback: token file (for setups where the Supervisor options dialog is
    # unreachable or protection mode blocks the API)
    if not token:
        for p in (Path("/data/.token"), Path("/app/.token"), Path("/addons/ps4_jb_host/.token"), Path("/config/.token"), Path("/share/ps4jb/.token")):
            try:
                token = p.read_text().strip()
                if token:
                    break
            except OSError:
                pass
    if token:
        opts["github_token"] = token
    manifest = read_goldhen_manifest()

    try:
        remote = goldhen_remote(token)
    except urllib.error.HTTPError as exc:
        log(f"goldhen check: github {exc.code} (rate limit? add github_token)")
        return manifest
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log(f"goldhen check failed: {exc}")
        return manifest
    if not remote:
        log("goldhen check: no matching asset")
        return manifest

    have = manifest.get("version")
    if have == remote["version"] and not force:
        return manifest

    target = dest_dir / remote["name"]
    stable = dest_dir / "goldhen.bin"
    try:
        size, sha = _download(remote["url"], target, token)
    except (urllib.error.URLError, OSError) as exc:
        log(f"goldhen download failed: {exc}")
        return manifest

    shutil.copyfile(target, stable)
    manifest = {
        "version": remote["version"],
        "file": remote["name"],
        "path": str(stable),
        "size": size,
        "sha256": sha,
        "source": remote["url"],
        "fetched_at": time.time(),
    }
    GOLDHEN_JSON.write_text(json.dumps(manifest, indent=2))
    with state_lock:
        state["goldhen"] = manifest
    log(f"goldhen {remote['version']} → {stable} ({size} B, sha256 {sha[:12]}…)")
    # Re-pin WebKitty to the new version if it's already unpacked
    if (WEBKITTY_DIR / "index.html").exists():
        _pin_webkitty_goldhen()
    # Publish to GitHub if configured
    if opts.get("github_auto_push") and opts.get("github_token"):
        github_push_latest(opts, manifest.get("version", ""))
    return manifest


def goldhen_loop(opts):
    interval = max(600, int(opts.get("goldhen_check_interval") or 3600))
    while True:
        if opts.get("goldhen_auto_update", True):
            sync_goldhen(opts)
        time.sleep(interval)


# ------------------------------------------------------- console probing


def port_open(host, port, timeout=1.0):
    if not host:
        return False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def send_payload(host, blob, length_prefix=False):
    """GoldHEN BinLoader: raw bytes to :9090. Optional 4-byte LE length header
    for loaders that expect it (PS4 Payload Sender style)."""
    if not blob:
        raise ValueError("empty payload")
    with socket.create_connection((host, BINLOADER_PORT), timeout=10) as sock:
        if length_prefix:
            sock.sendall(struct.pack("<I", len(blob)))
        sock.sendall(blob)
    return len(blob)


def inject_file(host, path: Path, length_prefix=False):
    blob = path.read_bytes()
    n = send_payload(host, blob, length_prefix)
    log(f"injected {path.name} ({n} bytes)")
    return n


def auto_inject(opts):
    """Fire once per online transition. Files move to injected/ when inject_once."""
    src = Path(opts["payload_dir"])
    if not src.exists():
        return
    pending = sorted(p for p in src.glob("*.bin") if p.is_file())
    if not pending:
        return
    done = []
    for p in pending:
        try:
            inject_file(opts["ps4_host"], p)
            done.append(p.name)
            if opts.get("inject_once", True):
                dst = src / "injected"
                dst.mkdir(exist_ok=True)
                shutil.move(str(p), str(dst / p.name))
        except (OSError, ValueError) as exc:
            log(f"inject failed for {p.name}: {exc}")
            break
    with state_lock:
        state["injected"] = done
        state["last_inject"] = time.time() if done else state["last_inject"]


def supervisor_state(opts, force=False):
    token = os.environ.get("SUPERVISOR_TOKEN")
    if not token:
        return
    prefix = opts["entity_prefix"]
    payload = {
        "state": "jailbroken" if state["jailbroken"] else "offline",
        "attributes": {
            "friendly_name": "PS4 Jailbreak",
            "ps4_host": opts["ps4_host"],
            "binloader": state["binloader"],
            "ftp": state["ftp"],
            "klog": state["klog"],
            "last_inject": state["last_inject"],
            "injected": state["injected"],
            "host_mac": "addon",
        },
    }
    req = urllib.request.Request(
        f"http://supervisor/core/api/states/sensor.{prefix}_status",
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=5).read()
    except (urllib.error.URLError, OSError) as exc:
        log(f"supervisor state push failed: {exc}")


def poll_loop(opts):
    host = opts["ps4_host"]
    interval = max(5, int(opts["poll_interval"]))
    prev = False
    while True:
        binloader = port_open(host, BINLOADER_PORT)
        ftp = port_open(host, FTP_PORT)
        klog = port_open(host, KLOG_PORT)
        alive = binloader or ftp or klog
        with state_lock:
            state.update(
                jailbroken=alive,
                binloader=binloader,
                ftp=ftp,
                klog=klog,
                last_check=time.time(),
            )
        if alive and not prev:
            log("console online — GoldHEN detected")
            if opts["auto_inject"] and binloader:
                auto_inject(opts)
        if not alive and prev:
            log("console offline")
        prev = alive
        supervisor_state(opts)
        time.sleep(interval)


# ---------------------------------------------------------------- fake DNS


def _parse_qname(pkt):
    i = 12
    labels = []
    while i < len(pkt):
        ln = pkt[i]
        if ln == 0:
            i += 1
            break
        if ln & 0xC0:
            i += 2
            break
        labels.append(pkt[i + 1 : i + 1 + ln].decode("latin-1"))
        i += 1 + ln
    if i + 4 > len(pkt):
        return None, None, None
    qtype, qclass = struct.unpack(">HH", pkt[i : i + 4])
    return ".".join(labels).lower().rstrip("."), qtype, i + 4


def _answer(pkt, qend, qtype, ip):
    tid = pkt[:2]
    flags = b"\x81\x80"
    question = pkt[12:qend]
    if qtype == 1:
        body = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
        return tid + flags + struct.pack(">HHHH", 1, 1, 0, 0) + question + body
    # AAAA / others: NOERROR, no answers — the browser falls back to IPv4
    return tid + flags + struct.pack(">HHHH", 1, 0, 0, 0) + question


def dns_loop(opts):
    up = opts["dns_upstream"]
    host_ip = opts["host_ip"]
    intercept = {d.lower().rstrip(".") for d in opts["intercept_domains"]}
    blocked = {d.lower().rstrip(".") for d in opts["block_domains"]}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", int(opts["dns_port"])))
    except OSError as exc:
        log(f"DNS bind failed on :{opts['dns_port']} — {exc}")
        log("set dns_enabled=false or move HA's resolver off :53")
        return
    log(f"DNS sink live on :{opts['dns_port']} → {host_ip}")
    while True:
        try:
            pkt, peer = sock.recvfrom(1500)
        except OSError:
            continue
        name, qtype, qend = _parse_qname(pkt)
        if not name:
            continue
        if name in intercept or any(name.endswith("." + d) for d in intercept):
            sock.sendto(_answer(pkt, qend, qtype, host_ip), peer)
            continue
        if name in blocked or any(name.endswith("." + d) for d in blocked):
            sock.sendto(_answer(pkt, qend, qtype, "0.0.0.0"), peer)
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as fwd:
                fwd.settimeout(2.0)
                fwd.sendto(pkt, (up, 53))
                sock.sendto(fwd.recvfrom(1500)[0], peer)
        except OSError:
            pass


# ---------------------------------------------------------------- HTTP host


class Handler(SimpleHTTPRequestHandler):
    opts = None

    def __init__(self, *a, **kw):
        super().__init__(*a, directory=str(WEBKITTY_DIR), **kw)

    def log_message(self, fmt, *args):
        log("http " + fmt % args)

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/api/status":
            with state_lock:
                snap = dict(state)
            snap["ps4_host"] = self.opts["ps4_host"]
            snap["host_ip"] = self.opts["host_ip"]
            snap["uptime"] = int(time.time() - START)
            return self._json(snap)
        if u.path == "/api/goldhen":
            manifest = read_goldhen_manifest()
            manifest.setdefault("auto_update", self.opts.get("goldhen_auto_update"))
            return self._json(manifest)
        if u.path in ("/goldhen.bin", "/api/goldhen/download"):
            stable = Path(self.opts["goldhen_dir"]) / "goldhen.bin"
            if not stable.exists():
                stable = Path(read_goldhen_manifest().get("path", ""))
            if not stable or not stable.is_file():
                return self._json({"ok": False, "error": "no payload yet"}, 404)
            blob = stable.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(blob)))
            self.send_header("Content-Disposition", f'attachment; filename="{stable.name}"')
            self.end_headers()
            self.wfile.write(blob)
            return
        if u.path == "/api/payloads":
            src = Path(self.opts["payload_dir"])
            files = sorted(p.name for p in src.glob("*.bin")) if src.exists() else []
            return self._json({"dir": str(src), "files": files})
        if u.path == "/api/inject":
            qs = parse_qs(u.query)
            name = (qs.get("file") or [""])[0]
            if not name:
                return self._json({"ok": False, "error": "file param required"}, 400)
            path = Path(self.opts["payload_dir"]) / Path(name).name
            if not path.exists():
                return self._json({"ok": False, "error": "not found"}, 404)
            try:
                n = inject_file(self.opts["ps4_host"], path)
            except (OSError, ValueError) as exc:
                return self._json({"ok": False, "error": str(exc)}, 502)
            return self._json({"ok": True, "bytes": n})
        if u.path == "/":
            self.path = self.opts["landing_path"] or "/"
        return super().do_GET()

    def do_POST(self):
        u = urlparse(self.path)
        if u.path == "/api/goldhen/update":
            manifest = sync_goldhen(self.opts, force=True)
            return self._json({"ok": bool(manifest), **manifest})
        if u.path != "/api/inject":
            return self._json({"ok": False, "error": "unknown route"}, 404)
        length = int(self.headers.get("Content-Length") or 0)
        blob = self.rfile.read(length) if length else b""
        if not blob:
            return self._json({"ok": False, "error": "empty body"}, 400)
        try:
            n = send_payload(self.opts["ps4_host"], blob)
        except (OSError, ValueError) as exc:
            return self._json({"ok": False, "error": str(exc)}, 502)
        with state_lock:
            state["last_inject"] = time.time()
        return self._json({"ok": True, "bytes": n})

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


START = time.time()


def main():
    opts = load_options()
    opts["host_ip"] = opts.get("host_ip") or lan_ip()

    for d in (WEBKITTY_DIR.parent, Path(opts["payload_dir"]), Path(opts["goldhen_dir"])):
        d.mkdir(parents=True, exist_ok=True)

    with state_lock:
        state["goldhen"] = read_goldhen_manifest()

    threading.Thread(target=goldhen_loop, args=(opts,), daemon=True).start()

    if not sync_webkitty(force=os.environ.get("UPDATE_WEBKITTY", "0") == "1"):
        log("serving fallback page — no WebKitty checkout")

    if not (WEBKITTY_DIR / "index.html").exists():
        (WEBKITTY_DIR / "index.html").write_text(
            "<!doctype html><meta charset=utf-8><title>ps4 jb host</title>"
            "<body style='font:16px system-ui;padding:2rem'>"
            "<h1>Host up, WebKitty not downloaded</h1>"
            "<p>Check the add-on log. The container needs egress to github.com "
            "on first start.</p>"
        )

    Handler.opts = opts
    srv = ThreadingHTTPServer(("0.0.0.0", int(opts["http_port"])), Handler)
    srv.daemon_threads = True

    threads = [threading.Thread(target=srv.serve_forever, daemon=True)]
    if opts["dns_enabled"]:
        threads.append(threading.Thread(target=dns_loop, args=(opts,), daemon=True))
    threads.append(threading.Thread(target=poll_loop, args=(opts,), daemon=True))
    for t in threads:
        t.start()

    log(f"host up: http://{opts['host_ip']}:{opts['http_port']}/  ps4={opts['ps4_host'] or 'unset'}")
    log("point the PS4 browser (or fake-DNS User's Guide) at that URL")

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    stop.wait()
    log("shutting down")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
