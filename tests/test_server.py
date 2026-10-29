"""Servers (SSH) add-on tests. Run with Hisho's venv at the repository's top:
~/code/hisho/.venv/bin/python -m pytest -q"""
import json
import subprocess
from pathlib import Path

import pytest
import yaml

from hisho import addon_store, addons, fleet_power, maintenance  # noqa: F401
from hisho.addon_testing import AUTH, TOKEN, Recorder

HERE = Path(__file__).resolve().parents[1]


def ctx_for(addon):
    return addons.Context(addon, resolve=lambda name: f"value-of-{name}")


def test_manifest_is_valid_and_readme_matches(addon):
    assert addons.validate_manifest(addon.manifest) == []
    assert addon_store.readme_problems(HERE) == []


def test_the_server_integration_reads_a_probe_and_flags_problems(fleet, monkeypatch):
    srv = addons.get("server")
    mod = addons.provider(srv)
    probe = {"os": ["Ubuntu 24.04 LTS", "6.8"], "uptime": ["up 2 weeks"], "mem": ["8000 3000"],
             "disk": ["/dev/sda1 100G 90G 10G 90% /"], "updates": ["openssl/noble 3.0.13 amd64 [upgradable from: 3.0.10]"],
             "reboot": ["yes"], "failed": ["backup.service"],
             "docker": ["pangolin|fosrl/pangolin:1.23.0|Up 2 weeks (healthy)", "gerbil|fosrl/gerbil:1.2|Up 2 weeks",
                        "web|site:prod|Up 5 minutes (unhealthy)"]}
    monkeypatch.setattr(mod, "probe", lambda entry: probe)
    monkeypatch.setattr(mod, "_site_ok", lambda url: (url != "down.example.com", "200" if url != "down.example.com" else "502"))
    entries = {"vps": {"host": "203.0.113.5", "user": "me", "sites": "ok.example.com, down.example.com"}}
    s = mod.summary(entries, None)
    assert s["headline"] == "1 of 1 server reachable · 1 updates pending"
    assert sorted(p["title"] for p in s["problems"]) == ["down.example.com is down", "vps: backup.service failed",
                                                         "vps: container web is unhealthy"]
    [sec] = mod.details(entries, None)
    names = [i["name"] for i in sec["items"]]
    assert names[0] == "Updates: 1 pending · reboot needed" and "pangolin  (fosrl/pangolin:1.23.0)" in names
    disk = next(i for i in sec["items"] if i["id"] == "disk")
    assert disk["state"] == "warn" and disk["facts"] == ["/: 90G of 100G used (90%)"]


# ── Find it / Sign in once ────────────────────────────────────────────────

PUB = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHisHoTestKeyBlob000000000000000000000000000 hisho@core"


class FakeSSH:
    """Stands in for ssh-keygen and ssh: no real SSH anywhere. ``key_on_server`` flips once the install
    command ran with the right password (handed to the askpass helper through its environment)."""

    def __init__(self, password="right-pass", key_on_server=False):
        self.password, self.key_on_server, self.calls = password, key_on_server, []

    def run(self, cmd, timeout=30, env=None):
        self.calls.append((cmd, dict(env or {})))
        if cmd[0] == "ssh-keygen" and "-f" in cmd and "-y" not in cmd:
            key = Path(cmd[cmd.index("-f") + 1])
            key.write_text("PRIVATE")
            key.with_name(key.name + ".pub").write_text(PUB + "\n")
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if cmd[0] == "ssh" and "BatchMode=yes" in cmd:          # a key login
            return subprocess.CompletedProcess(cmd, 0 if self.key_on_server else 255, "",
                                               "" if self.key_on_server else "Permission denied (publickey).")
        if cmd[0] == "ssh":                                       # the one password login
            assert env["SSH_ASKPASS_REQUIRE"] == "force"
            helper = Path(env["SSH_ASKPASS"])
            said = subprocess.run([str(helper)], capture_output=True, text=True,
                                  env={"HISHO_ASKPASS_SECRET": env["HISHO_ASKPASS_SECRET"]}).stdout.strip()
            if said != self.password:
                return subprocess.CompletedProcess(cmd, 255, "", "user@203.0.113.5: Permission denied (password).")
            self.key_on_server = True
            return subprocess.CompletedProcess(cmd, 0, "HISHO_KEY_OK\n", "")
        raise AssertionError(cmd)


@pytest.fixture
def ssh_world(addon, monkeypatch, tmp_path):
    mod = addons.provider(addon)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    monkeypatch.setattr(mod, "KNOWN_HOSTS", tmp_path / "known_hosts")
    monkeypatch.setattr(mod, "scan_host_key", lambda host, port=22: (f"{host} ssh-ed25519 AAAAhostkey", "SHA256:pinned"))
    return mod


def test_the_manifest_offers_find_it_and_sign_in_once(addon):
    m = addon.manifest
    assert m["discover"][0]["tcp"] == 22 and m["discover"][0]["banner"] == "SSH-"
    assert m["connect"]["form"] == ["host", "user", "port"] and list(m["connect"]["fields"]) == ["password"]
    assert addons.validate_manifest(m) == []


def test_sign_in_once_makes_hishos_key_puts_it_on_and_then_uses_only_the_key(addon, ssh_world, tmp_path):
    fake = FakeSSH()
    out = ssh_world.connect({"host": "203.0.113.5", "user": "admin", "port": "2222", "password": "right-pass"}, fake)
    assert out["ok"], out
    assert out["entry"] == {"host": "203.0.113.5", "user": "admin", "port": 2222,
                            "key_file": "~/.ssh/hisho_servers_ed25519", "host_key": "SHA256:pinned"}
    assert (tmp_path / "home" / ".ssh" / "hisho_servers_ed25519").exists()
    assert "[203.0.113.5]:2222 ssh-ed25519 AAAAhostkey" in (tmp_path / "known_hosts").read_text()
    pw_calls = [(c, e) for c, e in fake.calls if c[0] == "ssh" and "BatchMode=no" in c]
    assert len(pw_calls) == 1
    cmd, env = pw_calls[0]
    assert "right-pass" not in " ".join(cmd) and env["HISHO_ASKPASS_SECRET"] == "right-pass"
    assert "PubkeyAuthentication=no" in cmd and "StrictHostKeyChecking=yes" in cmd and "-p" in cmd
    assert PUB.split()[1] in cmd[-1] and "authorized_keys" in cmd[-1]
    assert not Path(env["SSH_ASKPASS"]).exists()                   # the helper is gone afterwards
    key_calls = [c for c, e in fake.calls if c[0] == "ssh" and "BatchMode=yes" in c]
    assert len(key_calls) == 2 and all(c[-1] == "true" for c in key_calls)   # before (no) and after (yes)
    assert "right-pass" not in out["message"]


def test_sign_in_once_with_a_wrong_password_says_so_and_saves_nothing(addon, ssh_world):
    out = ssh_world.connect({"host": "203.0.113.5", "user": "admin", "password": "wrong-pass"}, FakeSSH())
    assert not out["ok"] and "refused the password" in out["error"] and "wrong-pass" not in out["error"]
    assert "password" in out["explain"]


def test_sign_in_once_when_the_key_already_logs_in_needs_no_password(addon, ssh_world):
    fake = FakeSSH(key_on_server=True)
    out = ssh_world.connect({"host": "203.0.113.5", "user": "admin", "password": ""}, fake)
    assert out["ok"] and "already logs in" in out["message"] and "port" not in out["entry"]
    assert not [c for c, e in fake.calls if c[0] == "ssh" and "BatchMode=no" in c]
    assert not ssh_world.connect({"host": "203.0.113.5", "user": "admin", "password": ""}, FakeSSH())["ok"]


def test_sign_in_once_through_core_keeps_no_password(addon, ssh_world, monkeypatch):
    from hisho import connect as core_connect
    fake = FakeSSH()
    monkeypatch.setattr(addons.Context, "run", lambda self, cmd, timeout=30, env=None: fake.run(cmd, timeout, env))
    monkeypatch.setattr(ssh_world, "test", lambda entry, ctx: {"ok": True, "fill": {"host_key": "SHA256:pinned"}})
    out = core_connect.connect(addon, "web1", {"host": "203.0.113.5", "user": "admin", "password": "right-pass"})
    assert out["ok"], out
    e = addons.read_config("server")["entries"]["web1"]
    assert e["key_file"] == "~/.ssh/hisho_servers_ed25519" and "password" not in e
    assert "right-pass" not in Path(addons.config_path("server")).read_text()


def test_the_install_command_adds_the_key_once_with_private_permissions(tmp_path, addon):
    mod = addons.provider(addon)
    home = tmp_path / "remote-home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAAother someone")       # no newline at the end
    script = mod.install_script(PUB)
    for _ in range(2):
        res = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env={"HOME": str(home), "PATH": "/usr/bin:/bin"})
        assert res.returncode == 0 and "HISHO_KEY_OK" in res.stdout, res.stderr
    lines = (home / ".ssh" / "authorized_keys").read_text().splitlines()
    assert lines == ["ssh-ed25519 AAAAother someone", f"{mod.KEY_OPTIONS} {PUB}"]
    assert oct((home / ".ssh").stat().st_mode & 0o777) == "0o700"
    assert oct((home / ".ssh" / "authorized_keys").stat().st_mode & 0o777) == "0o600"
