"""Servers over SSH for Hisho (see addon.yaml). Runs inside Core. Read-only.

Sign in once (``connect``): the owner types the server's address, a user and that user's password, once. Hisho
makes its own SSH key on the Core machine if it has none (``KEY_FILE``), pins the server's host key the way Add
does, logs in once with the password (OpenSSH asks a tiny askpass script for it; the password travels in that
one ssh process's environment, never on a command line, in a file or in a message) and adds Hisho's public key
to that user's ``~/.ssh/authorized_keys`` (the line's comment is ``hisho@<this machine>``). Then it checks the key
logs in on its own. The password is not kept. ``made`` in the entry records the key it put there.

Remove from server (``disconnect``): logs in with Hisho's own key and deletes only the authorized_keys line that
carries exactly Hisho's public key, leaving every other line (another Hisho's, yours) and the file's permissions.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

KNOWN_HOSTS = Path("~/.config/hisho/server-known_hosts").expanduser()
#: Hisho's own key for servers, made by Sign in once (entries added by hand default to ~/.ssh/id_ed25519)
KEY_FILE = "~/.ssh/hisho_servers_ed25519"
#: what Hisho's key may do on a server it was put on: run commands, nothing forwarded, no terminal
KEY_OPTIONS = "no-agent-forwarding,no-port-forwarding,no-X11-forwarding,no-pty"

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


# ── sign in once ──────────────────────────────────────────────────────────

_ASKPASS = "#!/bin/sh\nprintf '%s\\n' \"$HISHO_ASKPASS_SECRET\"\n"


def _run(ctx: Any, cmd: list[str], timeout: int = 30, env: dict[str, str] | None = None) -> Any:
    if ctx is not None and hasattr(ctx, "run"):
        return ctx.run(cmd, timeout=timeout, env=env)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env={**os.environ, **(env or {})})


def _machine() -> str:
    """This machine's name for the key's comment (lower-case letters, digits and dashes)."""
    try:
        from hisho import fleet_config
        name = fleet_config.local_name()
    except Exception:  # noqa: BLE001
        name = socket.gethostname()
    return re.sub(r"[^a-z0-9-]+", "-", str(name).split(".")[0].lower()).strip("-")[:40].strip("-") or "hisho"


def key_fingerprint(pub: str) -> str:
    """SHA256 fingerprint of a public key line, as ``ssh-keygen -l`` shows it."""
    blob = base64.b64decode(pub.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def authorized_line(pub: str) -> str:
    """The authorized_keys line Hisho adds: its key, limited by KEY_OPTIONS, with the comment ``hisho@<machine>``
    (so the owner can tell which Hisho put it there; the key file's own comment is left as it is)."""
    kind, blob = pub.split()[:2]
    return f"{KEY_OPTIONS} {kind} {blob} hisho@{_machine()}"


def ensure_key(ctx: Any, key_file: str = KEY_FILE) -> str:
    """Hisho's public key line, making the ed25519 key pair first if there is none (no passphrase: Core uses it
    unattended; the private half stays on the Core machine, mode 600)."""
    key = Path(key_file).expanduser()
    pub = key.with_name(key.name + ".pub")
    if not key.exists():
        key.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        res = _run(ctx, ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", f"hisho@{_machine()}",
                         "-f", str(key)], timeout=30)
        if res.returncode != 0 or not key.exists():
            raise RuntimeError(f"couldn't make Hisho's SSH key {key_file}: {(res.stderr or '').strip()[-160:]}")
    if not pub.exists():
        res = _run(ctx, ["ssh-keygen", "-y", "-f", str(key)], timeout=15)
        if res.returncode != 0 or not res.stdout.strip():
            raise RuntimeError(f"couldn't read the public half of {key_file}")
        pub.write_text(res.stdout.strip() + "\n")
    line = pub.read_text().strip()
    if len(line.split()) < 2 or not line.startswith("ssh-"):
        raise RuntimeError(f"{pub} isn't an SSH public key")
    return line


def connect_copy(ctx: Any) -> dict[str, str]:
    """For a server that takes only keys (AWS Lightsail, a droplet made with an SSH key): one line to paste in its
    browser console, putting Hisho's key on it. Then Sign in once needs no password."""
    pub = ensure_key(ctx, KEY_FILE)
    line = authorized_line(pub)
    return {"label": "Hisho's key", "say": "For a server that takes only keys: paste this once in its console in the "
            "browser (it adds Hisho's key for that user), then leave the password empty below.",
            "copy": f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && grep -qF '{pub.split()[1]}' ~/.ssh/authorized_keys 2>/dev/null "
                    f"|| echo '{line}' >> ~/.ssh/authorized_keys; chmod 600 ~/.ssh/authorized_keys"}


def install_script(pub: str) -> str:
    """The one command run with the password: add Hisho's key to authorized_keys once (a key already there is
    left alone; HISHO_KEY_ADDED says it was added now), with the folder and file private as sshd wants them."""
    blob = pub.split()[1]
    line = authorized_line(pub)
    return ("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys"
            " && chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys"
            f" && if [ \"$(awk -v b={shlex.quote(blob)} '{{for (i = 1; i <= NF; i++) if ($i == b) {{c++; break}}}}"
            " END {print c + 0}' ~/.ssh/authorized_keys)\" -eq 0 ]; then"
            " if [ -s ~/.ssh/authorized_keys ] && [ -n \"$(tail -c 1 ~/.ssh/authorized_keys)\" ]; then"
            " echo >> ~/.ssh/authorized_keys; fi;"
            f" printf '%s\\n' {shlex.quote(line)} >> ~/.ssh/authorized_keys && echo HISHO_KEY_ADDED; fi"
            " && { command -v restorecon >/dev/null 2>&1 && restorecon -R ~/.ssh >/dev/null 2>&1; true; }"
            " && echo HISHO_KEY_OK")


def _password_args(entry: dict[str, Any]) -> list[str]:
    return ["ssh", "-T", "-o", "BatchMode=no", "-o", "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes",
            "-o", f"UserKnownHostsFile={KNOWN_HOSTS}", "-o", "PubkeyAuthentication=no",
            "-o", "PreferredAuthentications=keyboard-interactive,password", "-o", "NumberOfPasswordPrompts=1",
            "-o", "KbdInteractiveAuthentication=yes", "-o", "PasswordAuthentication=yes",
            "-p", str(entry.get("port") or 22), f"{entry['user']}@{entry['host']}"]


def _key_works(entry: dict[str, Any], ctx: Any) -> bool:
    try:
        res = _run(ctx, _ssh_args(entry) + ["true"], timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


def _with_password(entry: dict[str, Any], password: str, command: str, ctx: Any) -> Any:
    """Run one command on the server, signing in with the password through SSH_ASKPASS (OpenSSH 8.4+)."""
    with tempfile.TemporaryDirectory(prefix="hisho-askpass-") as tmp:
        helper = Path(tmp) / "askpass"
        helper.write_text(_ASKPASS)
        helper.chmod(0o700)
        env = {"SSH_ASKPASS": str(helper), "SSH_ASKPASS_REQUIRE": "force", "HISHO_ASKPASS_SECRET": password}
        return _run(ctx, _password_args(entry) + [command], timeout=40, env=env)


def connect(values: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Sign in once: put Hisho's own key on the server with the typed password, then use only the key."""
    host, user = str(values.get("host") or "").strip(), str(values.get("user") or "").strip()
    if not host or not user:
        return {"ok": False, "error": "type the server's address and the user to log in as"}
    port = int(values.get("port") or 22)
    password = str(values.get("password") or "")
    entry = {"host": host, "user": user, "port": port, "key_file": KEY_FILE}
    pub = ensure_key(ctx)
    _, fp = scan_host_key(host, port)
    entry["host_key"] = fp
    _trust(entry)
    already = _key_works(entry, ctx)
    if not already:
        if not password:
            return {"ok": False, "error": f"Hisho's key doesn't log in to {user}@{host} yet: type that user's "
                                          "password so Hisho can put its key there"}
        res = _with_password(entry, password, install_script(pub), ctx)
        if res.returncode != 0 or "HISHO_KEY_OK" not in (res.stdout or ""):
            err = (res.stderr or "").strip().replace(password, "***")[-200:]
            if "permission denied" in err.lower():
                return {"ok": False, "error": f"{host} refused the password for {user}: {err}",
                        "explain": "The server answered, but it refused that user and password. Check both, and "
                                   "that the server allows password logins (some allow only keys: then put "
                                   "Hisho's key on it by hand, see the SSH key help)."}
            return {"ok": False, "error": err or f"couldn't put Hisho's key on {host}"}
        if not _key_works(entry, ctx):
            return {"ok": False, "error": f"Hisho's key is on {host} now, but logging in with it still fails "
                                          "(does the server allow key logins? PubkeyAuthentication in sshd_config)"}
    port_part = "" if port == 22 else f" port {port}"
    say = "already logs in" if already else "is on the server now"
    out = {"host": host, "user": user, "key_file": KEY_FILE, "host_key": fp, **({"port": port} if port != 22 else {})}
    if not already and "HISHO_KEY_ADDED" in (res.stdout or ""):
        out["made"] = {"key": key_fingerprint(pub), "comment": f"hisho@{_machine()}"}     # for Remove from server
    return {"ok": True, "entry": out,
            "message": f"Hisho's own SSH key {say} for {user}@{host}{port_part}; the password was used once and "
                       f"not kept. Host key {fp} pinned."
                       + (" Its line was there before, so Remove from server is not offered for it." if "made" not in out else "")}


# ── Remove from server: take Hisho's own key line out again ──────────────

def remove_script(pub: str) -> str:
    """The one command run with Hisho's key: delete from ``~/.ssh/authorized_keys`` every line that carries exactly
    Hisho's key (a whole field equal to its blob), keeping every other line. The file is rewritten in place (same
    file, owner and permissions). Says HISHO_REMOVED <lines> and HISHO_GONE (or HISHO_STILL)."""
    b = shlex.quote(pub.split()[1])
    f = '"$HOME/.ssh/authorized_keys"'
    count = f"awk -v b={b} '{{for (i = 1; i <= NF; i++) if ($i == b) {{c++; break}}}} END {{print c + 0}}' \"$f\""
    return (f"f={f}; if [ ! -f \"$f\" ]; then echo HISHO_GONE; echo HISHO_REMOVED 0; exit 0; fi;"
            f" n=$({count});"
            " if [ \"$n\" -gt 0 ]; then t=$(mktemp \"$HOME/.ssh/.hisho-authorized_keys.XXXXXX\") || exit 1;"
            f" awk -v b={b} '{{for (i = 1; i <= NF; i++) if ($i == b) next; print}}' \"$f\" > \"$t\""
            " && cat \"$t\" > \"$f\"; r=$?; rm -f \"$t\"; [ $r -eq 0 ] || exit 1; fi;"
            f" if [ \"$({count})\" -gt 0 ]; then echo HISHO_STILL; else echo HISHO_GONE; fi; echo HISHO_REMOVED $n")


def _public(key_file: str, ctx: Any) -> str:
    """The public half of Hisho's key (never makes one)."""
    key = Path(key_file).expanduser()
    pub = key.with_name(key.name + ".pub")
    if pub.exists():
        return pub.read_text().strip()
    res = _run(ctx, ["ssh-keygen", "-y", "-f", str(key)], timeout=15) if key.exists() else None
    if not res or res.returncode != 0 or not res.stdout.strip():
        raise RuntimeError(f"Hisho's key {key_file} is not on this machine any more, so it can't log in to take "
                           "its line out; remove it from the server's authorized_keys yourself")
    return res.stdout.strip()


def disconnect(entry: dict[str, Any], login: dict[str, Any], ctx: Any) -> dict[str, Any]:
    """Remove from server: log in with Hisho's own key (host key pinned) and delete only the authorized_keys line
    with exactly that key, the one Sign in once put there (``made``). No login is asked: the key removes itself."""
    made = entry.get("made") or {}
    if not isinstance(made, dict) or not made.get("key"):
        return {"ok": False, "error": "Hisho didn't put its key on this server by signing in once, so there is "
                                      "nothing of Hisho's to remove; take the key out of authorized_keys yourself"}
    pub = _public(str(entry.get("key_file") or KEY_FILE), ctx)
    if key_fingerprint(pub) != made["key"]:
        return {"ok": False, "error": f"Hisho's key file is not the key it put on {entry['host']} ({made['key']}), so "
                                      "it removed nothing; take that key out of authorized_keys yourself"}
    _trust(entry)
    where = f"{entry['user']}@{entry['host']}"
    res = _run(ctx, _ssh_args(entry) + [remove_script(pub)], timeout=30)
    text = res.stdout or ""
    if res.returncode != 0 or "HISHO_REMOVED" not in text:
        err = (res.stderr or "").strip()[-200:]
        if "permission denied" in err.lower():
            return {"ok": True, "message": f"Hisho's key no longer logs in to {where}, so its line was already gone. "
                                           "Nothing was changed there."}
        return {"ok": False, "error": err or f"couldn't take Hisho's key out on {entry['host']}"}
    n = int((re.search(r"HISHO_REMOVED (\d+)", text) or [0, "0"])[1])
    if "HISHO_STILL" in text or _key_works(entry, ctx):
        return {"ok": False, "error": f"Hisho took {n} line(s) out of {where}'s authorized_keys, but its key still "
                                      "logs in (is it in another authorized keys file?); Hisho kept the entry"}
    if not n:
        return {"ok": True, "message": f"Hisho's key line was already gone from {where}'s authorized_keys. Nothing "
                                       "else was changed."}
    return {"ok": True, "message": f"Took Hisho's key ({made.get('comment') or made['key']}) out of {where}'s "
                                   "authorized_keys; every other line is as it was, and Hisho's key no longer logs in."}
