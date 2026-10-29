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


def test_the_install_command_adds_the_key_once_with_private_permissions(tmp_path, addon, monkeypatch):
    mod = addons.provider(addon)
    monkeypatch.setattr("hisho.fleet_config.local_name", lambda: "kihon")
    home = tmp_path / "remote-home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".ssh" / "authorized_keys").write_text("ssh-ed25519 AAAAother someone")       # no newline at the end
    script = mod.install_script(PUB)
    for _ in range(2):
        res = subprocess.run(["sh", "-c", script], capture_output=True, text=True, env={"HOME": str(home), "PATH": "/usr/bin:/bin"})
        assert res.returncode == 0 and "HISHO_KEY_OK" in res.stdout, res.stderr
    lines = (home / ".ssh" / "authorized_keys").read_text().splitlines()
    assert lines == ["ssh-ed25519 AAAAother someone", f"{mod.KEY_OPTIONS} {PUB.rsplit(' ', 1)[0]} hisho@kihon"]
    assert oct((home / ".ssh").stat().st_mode & 0o777) == "0o700"
    assert oct((home / ".ssh" / "authorized_keys").stat().st_mode & 0o777) == "0o600"



def test_a_vps_has_its_providers_steps_and_hishos_key_for_key_only_servers(addon, tmp_path, monkeypatch):
    """One Servers add-on for both: on your network (Found) and on the internet (a VPS provider's steps and link)."""
    from hisho import connect as hconnect
    places = hconnect.view(addon)["connect"]["places"]
    names = [x["name"] for x in places]
    assert names[0] == "DigitalOcean" and {"Hetzner", "Vultr", "AWS Lightsail"} <= set(names) and names[-1] == "Other"
    assert all(x["get"].startswith("https://") for x in places if x["name"] != "Other")
    import importlib.util, subprocess as sp
    spec = importlib.util.spec_from_file_location("srv", Path(__file__).resolve().parents[1] / "provider.py")
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
    key = tmp_path / "k"
    key.with_name("k.pub").write_text("ssh-ed25519 AAAAC3NzaTEST hisho@core\n")
    key.write_text("private")
    monkeypatch.setattr(mod, "KEY_FILE", str(key))
    got = mod.connect_copy(None)
    assert "AAAAC3NzaTEST" in got["copy"] and "authorized_keys" in got["copy"] and "no-pty" in got["copy"]
    assert "private" not in got["copy"]


# ── names carry this machine; Remove from server ──────────────────────────

class RemoteSSH(FakeSSH):
    """FakeSSH whose "server" is a folder: the commands Hisho sends really run there (``sh -c`` with HOME set to
    it), so the authorized_keys file is real. No network and no real ssh."""

    def __init__(self, home, password="right-pass"):
        super().__init__(password)
        self.home = home

    @property
    def key_on_server(self):
        ak = self.home / ".ssh" / "authorized_keys"
        return ak.exists() and any(PUB.split()[1] in l.split() for l in ak.read_text().splitlines())

    @key_on_server.setter
    def key_on_server(self, value):
        pass

    def sh(self, script):
        return subprocess.run(["sh", "-c", script], capture_output=True, text=True,
                              env={"HOME": str(self.home), "PATH": "/usr/bin:/bin"})

    def run(self, cmd, timeout=30, env=None):
        if cmd[0] == "ssh" and "BatchMode=no" in cmd:                # the password login runs the install
            got = super().run(cmd, timeout, env)
            if got.returncode:
                return got
            self.calls[-1] = (cmd, dict(env or {}))
            return self.sh(cmd[-1])
        if cmd[0] == "ssh" and "BatchMode=yes" in cmd and cmd[-1] != "true":
            self.calls.append((cmd, dict(env or {})))
            if not self.key_on_server:
                return subprocess.CompletedProcess(cmd, 255, "", "admin@203.0.113.5: Permission denied (publickey).")
            return self.sh(cmd[-1])
        return super().run(cmd, timeout, env)


OWNER = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOwnerKey00000000000000000000000000000000000 me@laptop"
LIVE = "no-pty ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILiveHishoKey000000000000000000000000000000 hisho@kihon"
NEAR = f"ssh-ed25519 {PUB.split()[1]}X not-quite-hishos"                # a blob that only starts with Hisho's


@pytest.fixture
def remote(ssh_world, tmp_path, monkeypatch):
    monkeypatch.setattr("hisho.fleet_config.local_name", lambda: "Test_Box")     # this machine: test-box
    home = tmp_path / "remote-home"
    (home / ".ssh").mkdir(parents=True, mode=0o700)
    ak = home / ".ssh" / "authorized_keys"
    ak.write_text("\n".join([OWNER, LIVE, NEAR]) + "\n")
    ak.chmod(0o600)
    return ssh_world, RemoteSSH(home), ak


def test_the_line_hisho_adds_names_this_machine_and_made_records_it(remote):
    mod, fake, ak = remote
    out = mod.connect({"host": "203.0.113.5", "user": "admin", "password": "right-pass"}, fake)
    assert out["ok"], out
    lines = ak.read_text().splitlines()
    assert lines[:3] == [OWNER, LIVE, NEAR]
    assert lines[3] == f"{mod.KEY_OPTIONS} ssh-ed25519 {PUB.split()[1]} hisho@test-box"
    assert out["entry"]["made"] == {"key": mod.key_fingerprint(PUB), "comment": "hisho@test-box"}
    assert out["entry"]["made"]["key"].startswith("SHA256:") and PUB.split()[1] not in str(out["entry"]["made"])
    pub = Path(mod.KEY_FILE).expanduser().with_name("hisho_servers_ed25519.pub")
    assert pub.read_text().strip() == PUB                                   # the key file is left as it is


def test_a_key_that_already_logs_in_records_nothing_to_remove(remote):
    mod, fake, ak = remote
    ak.write_text(ak.read_text() + f"{PUB}\n")                              # put there some other way
    out = mod.connect({"host": "203.0.113.5", "user": "admin", "password": ""}, fake)
    assert out["ok"] and "made" not in out["entry"] and "not offered" in out["message"]


def test_remove_from_server_takes_out_only_hishos_line_and_keeps_permissions(remote):
    mod, fake, ak = remote
    entry = mod.connect({"host": "203.0.113.5", "user": "admin", "password": "right-pass"}, fake)["entry"]
    ak.write_text(ak.read_text() + "# a note\n" + f"command=\"x y\" {PUB.split()[0]} {PUB.split()[1]} copy\n")
    inode = ak.stat().st_ino
    out = mod.disconnect(entry, {}, fake)
    assert out["ok"], out
    assert ak.read_text().splitlines() == [OWNER, LIVE, NEAR, "# a note"]
    assert ak.stat().st_ino == inode and oct(ak.stat().st_mode & 0o777) == "0o600"
    assert not list(ak.parent.glob(".hisho-*"))                              # no temp file left
    assert "no longer logs in" in out["message"]
    sent = [c for c, e in fake.calls if c[0] == "ssh" and "BatchMode=yes" in c and c[-1] != "true"]
    assert len(sent) == 1 and "StrictHostKeyChecking=yes" in sent[0] and not [c for c, e in fake.calls[-3:] if "BatchMode=no" in c]
    again = mod.disconnect(entry, {}, fake)                                  # gone already: fine, nothing changed
    assert again["ok"] and "already gone" in again["message"]
    assert ak.read_text().splitlines() == [OWNER, LIVE, NEAR, "# a note"]


def test_remove_from_server_refuses_without_made_or_with_another_key(remote, monkeypatch, tmp_path):
    mod, fake, ak = remote
    entry = mod.connect({"host": "203.0.113.5", "user": "admin", "password": "right-pass"}, fake)["entry"]
    before = ak.read_text()
    assert not mod.disconnect({k: v for k, v in entry.items() if k != "made"}, {}, fake)["ok"]
    other = {**entry, "made": {"key": "SHA256:someone-elses", "comment": "hisho@kihon"}}
    got = mod.disconnect(other, {}, fake)
    assert not got["ok"] and "removed nothing" in got["error"]
    assert ak.read_text() == before
    monkeypatch.setattr(mod, "scan_host_key", lambda host, port=22: ("x ssh-ed25519 AAAAother", "SHA256:changed"))
    with pytest.raises(PermissionError):
        mod.disconnect(entry, {}, fake)
    assert ak.read_text() == before


def test_remove_through_core_forgets_the_entry(addon, remote, monkeypatch):
    from hisho import connect as core_connect
    mod, fake, ak = remote
    monkeypatch.setattr(addons.Context, "run", lambda self, cmd, timeout=30, env=None: fake.run(cmd, timeout, env))
    monkeypatch.setattr(mod, "test", lambda entry, ctx: {"ok": True, "fill": {"host_key": "SHA256:pinned"}})
    assert core_connect.connect(addon, "web1", {"host": "203.0.113.5", "user": "admin", "password": "right-pass"})["ok"]
    assert addons.read_config("server")["entries"]["web1"]["made"]["comment"] == "hisho@test-box"
    assert core_connect.view(addon)["disconnect"]["fields"] == {}
    out = core_connect.disconnect(addon, "web1", {})
    assert out["ok"], out
    assert "web1" not in (addons.read_config("server").get("entries") or {})
    assert ak.read_text().splitlines() == [OWNER, LIVE, NEAR]
