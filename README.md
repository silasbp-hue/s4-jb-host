# PS4 Jailbreak Host — HA OS add-on

Self-hosts WebKitty (ArabPixel) for PS4 FW **14.00**, plus a GoldHEN BinLoader
injector that fires automatically when the console comes back online.

## Install

```bash
# from a machine with ssh/git access to the HA box
scp -r ps4-jb-addon root@homeassistant:/addons/ps4_jb_host
```

In HA → Settings → Add-ons → Add-on Store → ⋮ → Check for updates →
**PS4 Jailbreak Host** → Install → Start.

The container clones `github.com/ArabPixel/WebKitty` into `/data/webkitty` on
first start (needs egress to github.com once). It survives add-on updates.

## Config

| key | default | meaning |
|---|---|---|
| `ps4_host` | `""` | console LAN IP, e.g. `192.168.1.50` |
| `host_ip` | auto | HA box IP as seen by the PS4; override if you have VLANs |
| `http_port` | `8080` | exploit page. Set `80` if you want the User's Guide trick |
| `landing_path` | `/` | deep link into WebKitty, e.g. `/index.html?fw=14.00` |
| `dns_enabled` | `false` | fake DNS for `manuals.playstation.net` |
| `dns_port` | `53` | must be 53 for the PS4 to use it |
| `dns_upstream` | `1.1.1.1` | resolver used for everything else |
| `intercept_domains` | `manuals.playstation.net` | names answered with `host_ip` |
| `block_domains` | update hosts | answered `0.0.0.0`, stops FW pushes |
| `auto_inject` | `true` | push `payload_dir/*.bin` on online transition |
| `inject_once` | `true` | move sent files into `payload_dir/injected/` |
| `payload_dir` | `/share/ps4jb/auto` | Samba-visible drop folder |
| `goldhen_dir` | `/share/ps4jb/payloads` | where the auto-fetched GoldHEN lands |
| `goldhen_auto_update` | `true` | poll GamerHack/g2all for a newer build |
| `goldhen_check_interval` | `3600` | seconds between checks (min 600) |
| `github_token` | `""` | raises the 60 req/h anonymous API cap |
| `poll_interval` | `15` | seconds between port checks |

## GoldHEN auto-update

On start and every `goldhen_check_interval`, the add-on reads
`api.github.com/repos/GamerHack/GamerHack.github.io/contents/g2all`, picks the
highest `goldhen_<maj>.<maj>b<build>.<rev>.bin`, downloads it, and writes:

```
/share/ps4jb/payloads/goldhen_<ver>.bin   versioned copy
/share/ps4jb/payloads/goldhen.bin         stable name, what gets served
/data/goldhen.json                        version, size, sha256, source, timestamp
```

Downloaded to `.part` then renamed — a dropped connection never leaves a
truncated payload. A failed check keeps the last good file; nothing is deleted.

Served at `http://<HA_IP>:8080/goldhen.bin` for hosts that pull the payload by
URL, and `POST /api/goldhen/update` forces a check now. `GET /api/goldhen`
returns the current manifest.

## Endpoints

```
GET  /api/status                 -> {jailbroken, binloader, ftp, klog, ...}
GET  /api/payloads               -> queued .bin files
GET  /api/inject?file=x.bin      -> push that file to :9090
POST /api/inject  (raw body)     -> push arbitrary .bin bytes
```

## Three levels of automation

**1. Manual, once per boot.** PS4 browser → `http://<HA_IP>:8080/` → pick 14.00
→ Jailbreak → GoldHEN loads.

**2. One tap, no typing.** Turn on `dns_enabled`, set the PS4 DNS to the HA box,
open **Settings → User's Guide**. The fake DNS sends `manuals.playstation.net`
to the add-on and the page loads itself. Requires `http_port: 80` and a free
port 53 — HA OS ships its own resolver on 53, so check
`ha dns info` first, or point the console at a router that can do the A record.

**3. Rest mode.** GoldHEN survives rest mode on 14.00. Only a cold boot needs
step 1 or 2; FTP 2121, klog 3232 and binloader 9090 stay alive across
suspend/resume.

## Payload auto-push

Anything dropped in `/share/ps4jb/auto/*.bin` is sent to port 9090 the moment
the add-on sees the console up. Good for plugin payloads, GDBServer, block-update
bins. BinLoader must be enabled in GoldHEN settings — off by default.

## Notes

- WebKitty is AGPLv3. Fine to self-host; don't redistribute a modified build
  without source.
- GoldHEN 2.4b18.13 is the payload WebKitty ships for 14.00. Payload is per-boot.
- No auth on the HTTP host. LAN only, never port-forward it.
