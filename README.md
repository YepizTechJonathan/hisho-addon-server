# Servers (SSH) (Hisho add-on)

## What it does

Watches Linux servers over SSH that Hisho doesn't manage as fleet machines (a VPS, a cloud box),
read only: OS and uptime, disk and memory, pending updates, failed services, every Docker container
with its image (so app versions show), and the health of the websites it serves. Its entries also
feed Hisho's machine list (`hisho inventory`) and other add-ons (CrowdSec, UniFi exposure checks).

## What it needs

- You need:
  - A Linux server you can reach over SSH (a VPS, a cloud box)
  - An SSH key on the Core machine that logs in to it
- Runs on: the Core machine, inside Hisho Core
- One entry per server, each with:
  - `host` (str, required)
  - `user` (str, required)
  - `port` (port, optional)
  - `key_file` (str, optional)
  - `host_key` (str, optional)
  - `sudo` (bool, optional)
  - `sites` (str, optional)
  - `note` (str, optional)

## How to install

On the dashboard: **Add-ons > Store > Servers (SSH) > Install**. Or from a terminal:

```bash
hisho addon install server
```

Hisho takes the newest version from this repository and turns it on inside Hisho Core. Updates show as **Update
available** on its Store card; **Roll back** returns to the version before.

## How to use

Its card shows a server with low disk, failed services or a website down. Its page (**Add-ons > Servers (SSH)**) has each server's OS, uptime, disk, memory, updates, containers and websites. It only reads; CrowdSec and UniFi use its entries.

## Settings

Add a server on its page: host, SSH user, port (22 if empty), the private key on the Core machine
(`~/.ssh/id_ed25519` if empty), whether to use `sudo -n` for Docker and updates, and the websites
it serves. Add pins the server's SSH host key (shown in the result); if that key later changes,
Hisho stops instead of trusting it. Entries are kept in `~/Hisho/System/Config/Addons/server.yaml`.

## How to remove

**Add-ons > Store > Servers (SSH) > Remove**, or `hisho addon remove server`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/server.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
