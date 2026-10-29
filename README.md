# Servers (SSH) (Hisho add-on)

## What it does

Watches Linux servers over SSH that Hisho doesn't manage as fleet machines, at home or on the internet (a home server, a VPS, a cloud box),
read only: OS and uptime, disk and memory, pending updates, failed services, every Docker container
with its image (so app versions show), and the health of the websites it serves. Its entries also
feed Hisho's machine list (`hisho inventory`) and other add-ons (CrowdSec, UniFi exposure checks).

## What it needs

- You need:
  - A Linux server you can reach over SSH: on your home network or the internet (a home server, a VPS, a cloud box)
  - A user on it and that user's password (used once to put Hisho's own SSH key there), or an SSH key on the Core machine that already logs in
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

The page (**Add-ons > Servers (SSH)**) lists the SSH servers it finds on your network; **Use this** fills in the
address. **Sign in once** asks for the server's address, a user and that user's password. Hisho then:

- makes its own SSH key on the Core machine if it has none (`~/.ssh/hisho_servers_ed25519`, ed25519);
- pins the server's SSH host key (shown in the result);
- logs in once with the password (through OpenSSH's askpass, never on a command line or in a file) and adds its
  public key to that user's `~/.ssh/authorized_keys` (once, folder 700 and file 600), limited to running
  commands: no agent, port or X11 forwarding and no terminal;
- checks the key logs in on its own, then tests the server and saves it. The password is not kept.

The user needs no root: Hisho only reads. Turn on **Use sudo** afterwards if Docker or the update check needs
`sudo -n` (passwordless) there. A server that allows only key logins can't take a password: add it by hand.

**+ add by filling in every field yourself** takes a key file instead (`~/.ssh/id_ed25519` if empty) whose public
half is already on the server. Either way, if the server's host key later changes, Hisho stops instead of
trusting it. Entries are kept in `~/Hisho/System/Config/Addons/server.yaml`.

## How to remove

**Add-ons > Store > Servers (SSH) > Remove**, or `hisho addon remove server`. Its card and page go away; your settings stay in `~/Hisho/System/Config/Addons/server.yaml`, so installing it again picks up where you left off.

## License

Source-available under the [PolyForm Shield License 1.0.0](LICENSE.md): free to use, change and share,
for any purpose except offering a product that competes with Hisho (reselling it, for example).
