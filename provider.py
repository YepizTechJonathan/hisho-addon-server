"""Servers over SSH for Hisho (see addon.yaml). Runs inside Core. Read-only."""
from __future__ import annotations

import base64
import hashlib
import shlex
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

KNOWN_HOSTS = Path("~/.config/hisho/server-known_hosts").expanduser()

#: One round trip: each section starts with a marker line.
PROBE = r"""
echo '##os'; . /etc/os-release 2>/dev/null; echo "$PRETTY_NAME"; uname -r
echo '##uptime'; uptime -p 2>/dev/null || uptime
echo '##disk'; df -hP -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | tail -n +2
echo '##mem'; free -m | awk '/^Mem:/ {print $2, $3}'
echo '##updates'; if command -v apt >/dev/null; then apt list --upgradable 2>/dev/null | tail -n +2;
  elif command -v dnf >/dev/null; then dnf -q check-update 2>/dev/null; fi
echo '##reboot'; [ -f /var/run/reboot-required ] && echo yes || echo no
echo '##failed'; systemctl --failed --no-legend --plain 2>/dev/null | awk '{print $1}'
echo '##docker'; SUDO docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>&1 | head -200
"""


def _ssh_args(entry: dict[str, Any]) -> list[str]:
    key = Path(str(entry.get("key_file") or "~/.ssh/id_ed25519")).expanduser()
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-o", "IdentitiesOnly=yes", "-i", str(key),
            "-p", str(entry.get("port") or 22), f"{entry['user']}@{entry['host']}"]


def scan_host_key(host: str, port: int = 22) -> tuple[str, str]:
    """(known_hosts line, SHA256 fingerprint) of the server's ed25519 key."""
    res = subprocess.run(["ssh-keyscan", "-T", "8", "-t", "ed25519", "-p", str(port), host],
                         capture_output=True, text=True, timeout=20)
    line = next((l for l in res.stdout.splitlines() if l and not l.startswith("#")), "")
    if not line:
        raise RuntimeError(f"{host} did not answer on SSH port {port}")
    blob = base64.b64decode(line.split()[2])
    fp = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return line, fp


def _trust(entry: dict[str, Any]) -> None:
    """Make sure the pinned key is in Hisho's known_hosts; refuse if the server shows another one."""
    port = int(entry.get("port") or 22)
    line, fp = scan_host_key(entry["host"], port)
    if entry.get("host_key") and fp != entry["host_key"]:
        raise PermissionError(f"{entry['host']}'s SSH host key changed (now {fp}, pinned {entry['host_key']}). "
                              "Hisho won't connect until you check it and update the pin.")
    KNOWN_HOSTS.parent.mkdir(parents=True, exist_ok=True)
    existing = KNOWN_HOSTS.read_text().splitlines() if KNOWN_HOSTS.exists() else []
    if line not in existing:
        name = entry["host"] if port == 22 else f"[{entry['host']}]:{port}"
        parts = line.split()
        KNOWN_HOSTS.write_text("\n".join([l for l in existing if not l.startswith(name + " ")]
                                         + [" ".join([name] + parts[1:])]) + "\n")


def probe(entry: dict[str, Any]) -> dict[str, list[str]]:
    _trust(entry)
    script = PROBE.replace("SUDO ", "sudo -n " if entry.get("sudo") else "")
    res = subprocess.run(_ssh_args(entry) + ["bash -s"], input=script, capture_output=True, text=True, timeout=60)
    if res.returncode and not res.stdout:
        raise RuntimeError((res.stderr.strip() or "ssh failed")[-200:])
    out: dict[str, list[str]] = {}
    current = None
    for raw in res.stdout.splitlines():
        if raw.startswith("##"):
            current = raw[2:]
            out[current] = []
        elif current and raw.strip():
            out[current].append(raw.rstrip())
    return out


def containers(p: dict[str, list[str]]) -> list[dict[str, str]]:
    rows = []
    for l in p.get("docker") or []:
        parts = l.split("|")
        if len(parts) == 3:
            rows.append({"name": parts[0], "image": parts[1], "status": parts[2]})
    return rows


def _site_ok(url: str) -> tuple[bool, str]:
    url = url if "://" in url else f"https://{url}"
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="GET"), timeout=8) as r:
            return r.status < 400, str(r.status)
    except urllib.error.HTTPError as exc:
        return exc.code < 400 or exc.code in (401, 403), str(exc.code)
    except Exception as exc:  # noqa: BLE001
        return False, type(exc).__name__


def summary(entries: dict[str, dict[str, Any]], ctx: Any) -> dict[str, Any]:
    problems, updates, down = [], 0, 0
    for name, entry in entries.items():
        try:
            p = probe(entry)
        except Exception as exc:  # noqa: BLE001
            down += 1
            problems.append({"entry": name, "severity": "warn", "title": f"Can't reach server {name}",
                             "detail": str(exc)[:200]})
            continue
        updates += len(p.get("updates") or [])
        for c in containers(p):
            if "unhealthy" in c["status"] or c["status"].startswith(("Restarting", "Exited (1", "Dead")):
                word = "unhealthy" if "unhealthy" in c["status"] else c["status"].split(" (")[0].lower()
                problems.append({"entry": name, "severity": "warn", "title": f"{name}: container {c['name']} is {word}",
                                 "detail": f"{c['image']} · {c['status']}"})
        for f in p.get("failed") or []:
            problems.append({"entry": name, "severity": "warn", "title": f"{name}: {f} failed", "detail": "systemd service"})
        for site in [s.strip() for s in str(entry.get("sites") or "").split(",") if s.strip()]:
            ok, why = _site_ok(site)
            if not ok:
                problems.append({"entry": name, "severity": "critical", "title": f"{site} is down",
                                 "detail": f"served by {name}; answered {why}"})
    n = len(entries)
    return {"state": "warn" if problems else "ok",
            "headline": f"{n - down} of {n} server{'s' * (n != 1)} reachable · {updates} updates pending",
            "problems": problems}


def details(entries: dict[str, dict[str, Any]], ctx: Any) -> list[dict[str, Any]]:
    out = []
    for name, entry in entries.items():
        try:
            p = probe(entry)
        except Exception as exc:  # noqa: BLE001
            out.append({"title": name, "entry": name, "state": "down", "facts": [str(exc)[:200]], "items": []})
            continue
        mem = (p.get("mem") or ["0 0"])[0].split()
        upd = p.get("updates") or []
        items = [
            {"id": "updates", "name": f"Updates: {len(upd)} pending" + (" · reboot needed" if (p.get("reboot") or ["no"])[0] == "yes" else ""),
             "state": "warn" if upd else "up", "facts": [u.split(" [")[0] for u in upd[:60]] or ["up to date"], "actions": []},
            {"id": "disk", "name": "Disks", "state": "warn" if any(int((l.split() or ["0"])[4].rstrip("%") or 0) >= 85 for l in (p.get("disk") or []) if len(l.split()) >= 6) else "up",
             "facts": [f"{l.split()[5]}: {l.split()[2]} of {l.split()[1]} used ({l.split()[4]})" for l in p.get("disk") or [] if len(l.split()) >= 6],
             "actions": []},
        ]
        cs = containers(p)
        if cs:
            for c in cs:
                bad = "unhealthy" in c["status"] or not c["status"].startswith("Up")
                items.append({"id": f"c-{c['name']}", "name": f"{c['name']}  ({c['image']})",
                              "state": "down" if "unhealthy" in c["status"] else "off" if bad else "up",
                              "facts": [c["status"]], "actions": []})
        elif p.get("docker"):
            items.append({"id": "docker", "name": "Docker", "state": "warn", "facts": p["docker"][:3]
                          + ["(turn on 'Use sudo' if Docker needs root here)"], "actions": []})
        for f in p.get("failed") or []:
            items.append({"id": f"f-{f}", "name": f"Failed: {f}", "state": "down", "facts": [], "actions": []})
        for site in [s.strip() for s in str(entry.get("sites") or "").split(",") if s.strip()]:
            ok, why = _site_ok(site)
            items.append({"id": f"s-{site}", "name": f"Site {site}", "state": "up" if ok else "down",
                          "facts": [f"answered {why}"], "actions": []})
        out.append({"title": name, "entry": name, "state": "ok",
                    "facts": [f"{entry['user']}@{entry['host']}", " · ".join((p.get("os") or [])[:2]),
                              (p.get("uptime") or [""])[0], f"memory {mem[1]} of {mem[0]} MB used" if len(mem) == 2 else "",
                              f"host key {entry.get('host_key') or 'not pinned'}"]
                             + ([entry["note"]] if entry.get("note") else []),
                    "items": items})
    return out


def test(entry: dict[str, Any], ctx: Any) -> dict[str, Any]:
    try:
        _, fp = scan_host_key(entry["host"], int(entry.get("port") or 22))
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200]}
    if entry.get("host_key") and fp != entry["host_key"]:
        return {"ok": False, "error": f"the server's SSH host key is {fp}, not the pinned {entry['host_key']}"}
    try:
        p = probe({**entry, "host_key": fp})
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)[:200], "fill": {"host_key": fp}}
    return {"ok": True, "fill": {"host_key": fp},
            "message": f"Connected: {(p.get('os') or ['?'])[0]}, {len(containers(p))} containers, "
                       f"{len(p.get('updates') or [])} updates pending · host key {fp} pinned"}


def act(entries: dict[str, dict[str, Any]], ctx: Any, entry: str, item: str, action: str) -> dict[str, Any]:
    return {"ok": False, "error": "this integration is read-only"}
