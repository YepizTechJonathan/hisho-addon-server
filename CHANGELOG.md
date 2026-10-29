# Changelog

## 0.2.1

- Add has two paths: On my network (found devices named and sorted: likely servers first; network gear, management boards and gadgets, and what Hisho already has, folded away) and a server on the internet: pick the provider (DigitalOcean, IONOS, Hetzner, Linode, Vultr, OVHcloud, AWS Lightsail, Other) for its steps and a link to where it shows the address and login.
- For a server that takes only keys: one line with Hisho's key to paste in its browser console, then Sign in once needs no password.

## 0.2.0

- Find it: the page lists the SSH servers on your network (port 22 answering with an SSH banner); Use this fills in the address.
- Sign in once: type the address, a user and its password once. Hisho makes its own key (`~/.ssh/hisho_servers_ed25519`) if it has none, pins the host key, puts its public key in that user's authorized_keys (no forwarding, no terminal) and from then on logs in only with the key. The password goes to ssh through askpass and is not kept.

## 0.1.2

- Every field on its setup form says in plain words what it is, and links to where to get it (addon.yaml `help:`, shown by Hisho's dashboard).
- Any Linux server you reach over SSH counts: on your home network or the internet, not only a VPS.

## 0.1.1

- README says what you need (addon.yaml you_need) and how to use it; the README check requires both.

## 0.1.0

- Moved out of Hisho into its own repository (hisho-addon-server); installed from the add-on store.

