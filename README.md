# HTTPowl agent

A small program for your server. It reads your web server's access logs,
sends each visit to [HTTPowl](https://httpowl.net), and applies the blocks
you choose there to the server's firewall. Pure Go, standard library only.

## What it does

1. **Reports visits.** Finds the access logs of nginx, Apache, LiteSpeed,
   Caddy, Traefik or IIS by itself (or reads the paths you give it), follows
   them like `tail -f` (survives log rotation, remembers its place across
   restarts) and sends new lines in batches every 2 seconds.
2. **Applies blocks.** Every 30 seconds it fetches the block list and applies
   it: nftables (or iptables + ipset) on Linux, Windows Firewall on Windows.
3. **Says it's alive.** Once a minute: host name, detected web server, log
   files, firewall backend, last error.

It only **reads** logs. It never changes your website, its files or its database.

## Safety

- Blocks only affect **ports 80 and 443**. SSH and every other port are never touched.
- Always let through: the server's own IPs, IPs with an open SSH session, loopback,
  and the HTTPowl team's login IPs. A block range that contains one of them is skipped.
- Linux: one nftables table `inet httpowl`, replaced atomically. `httpowl-agent -cleanup`
  (or uninstalling) removes it and every block with it.
- The systemd unit limits it to reading logs and managing its own firewall table
  (no other capabilities, read-only system, 200 MB memory, 30% CPU).

## Install

Linux (root):
```bash
curl -sL https://httpowl.net/install | sudo sh -s -- --token owl_YOUR_TOKEN
```
Options: `--log /path/to/access.log` (repeatable), `--no-firewall`, `--uninstall`.

Windows / IIS (elevated PowerShell):
```powershell
$env:HTTPOWL_TOKEN="owl_YOUR_TOKEN"; iwr -useb https://httpowl.net/install.ps1 | iex
```

Check what it would read: `httpowl-agent -detect`. Logs: `journalctl -u httpowl-agent -f`.

## Develop and release

```bash
go test ./...          # parsers (all formats), tail + rotation, firewall safety, state file
deploy/release.sh      # build linux amd64/arm64 + windows amd64, publish to httpowl.net/dl/
```

```
cmd/httpowl-agent/   the command (flags: -config -token -server -log -detect -cleanup -version)
internal/agent/      run loop: ship batches, heartbeat, rule sync, bot watcher, firewalls
  logparse/          one parser per log format, auto-detected per line
  tail/              follow files by glob, rotation, saved offsets
  detect/            which web servers run here and where their logs are
  sys/               server IPs and live SSH peers (never blocked)
internal/wire/       JSON shapes shared with the API — keep identical to httpowl-api/internal/wire
deploy/              install.sh (Linux + systemd), install.ps1 (Windows), release.sh
```
