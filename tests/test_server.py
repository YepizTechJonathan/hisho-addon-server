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
