# WireGuard Laravel API (WGLA)

Stateless REST API and CLI for managing WireGuard VPN interfaces and peers. Built on Laravel 13 / PHP 8.5+. No database — all state lives in WireGuard `.conf` files and the kernel module.

## Requirements

- PHP 8.5+ with the `sodium` extension
- `wireguard-tools` (`wg`, `wg-quick`)
- Linux: systemd and `nftables` (`iptables` too if Docker or ufw manage the firewall). macOS: Homebrew's `wireguard-go` and bash, and `pfctl`
- `curl`
- The root helper `bin/wgla-helper`, installed root-owned and allowed in sudoers (see [Setup](#setup))
- IP forwarding enabled (if using forward/NAT features)

## Quick Start

```bash
composer install
cp .env.example .env
php artisan key:generate

# Set your API key (the API refuses every protected request without one)
echo "API_KEY=$(openssl rand -hex 32)" >> .env

# Show platform-specific setup instructions
php artisan wg:help

# Start the API
php artisan serve --port=25420
```

## Setup

The app runs as an unprivileged web server user. Everything that needs root goes through one small script, `bin/wgla-helper`, which is the only command that user may run with `sudo`:

- **Strict arguments.** It accepts a fixed set of commands (`conf-write wg0`, `up wg0`, `peer-remove wg0 <key>`, …) and validates every argument.
- **Strict configs.** It only writes wg-quick configs that contain what the app generates. The only hooks allowed are calls back into the helper's own firewall commands. So the web user can manage links, but it can't run other commands, read other files or plant `PostUp` hooks as root.
- **Plain sudoers line.** One line with no argument wildcards, so it works with classic `sudo` and with `sudo-rs`, which is the default on Ubuntu 25.10 and later and rejects the wildcard-based rules this app used to need.

`php artisan wg:help` prints these steps with the paths for your checkout. Replace `www-data` (Linux) or `_www` (macOS) with your web server user.

### Linux

```bash
sudo apt install wireguard-tools nftables curl php-cli php-mbstring php-xml php-curl

# IP forwarding (for forward/NAT)
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl --system

# The root helper: install again after every update of this app
sudo mkdir -p /usr/local/sbin
sudo install -o root -g root -m 755 bin/wgla-helper /usr/local/sbin/wgla-helper

echo 'www-data ALL=(root) NOPASSWD: /usr/local/sbin/wgla-helper' | sudo tee /etc/sudoers.d/wgla > /dev/null
sudo chmod 440 /etc/sudoers.d/wgla
sudo visudo -cf /etc/sudoers.d/wgla
```

### macOS

```bash
brew install wireguard-tools wireguard-go bash

# IP forwarding (for forward/NAT)
sudo sysctl -w net.inet.ip.forwarding=1

# pf anchors for the forward/NAT rules (one-time)
sudo bash -c 'cat >> /etc/pf.conf <<EOF

# WireGuard NAT anchors
nat-anchor "wg/*"
anchor "wg/*"
EOF'
sudo pfctl -f /etc/pf.conf

# The root helper: install again after every update of this app
sudo mkdir -p /usr/local/sbin
sudo install -o root -g wheel -m 755 bin/wgla-helper /usr/local/sbin/wgla-helper

echo '_www ALL=(root) NOPASSWD: /usr/local/sbin/wgla-helper' | sudo tee /etc/sudoers.d/wgla > /dev/null
sudo chmod 440 /etc/sudoers.d/wgla
sudo visudo -cf /etc/sudoers.d/wgla
```

### Firewall notes

- **Rules per link.** `forward` and `nat` are per-link rules. Linux uses an nftables table `inet wg_<link>`, and NAT only masquerades the link's own subnet. macOS uses a pf anchor `wg/<link>`.
- **Docker and ufw.** These drop forwarded traffic in iptables' `FORWARD` chain, which an nftables accept can't override. When that chain drops anything, the helper also adds two `ACCEPT` rules there, tagged `wgla:<link>`.
- **firewalld.** It isn't handled. Add the WireGuard interface to a zone that allows forwarding.

## Configuration

All settings are in `.env` — see `.env.example`. Key options:

| Variable | Description |
|----------|-------------|
| `API_KEY` | Shared secret for API authentication (required) |
| `WIREGUARD_HOSTNAME` | Endpoint hostname for client configs (auto-detected if empty) |
| `WIREGUARD_DNS` | Default DNS for client configs (default: `8.8.8.8`) |
| `WIREGUARD_KEEPALIVE` | Default PersistentKeepalive seconds (default: `25`) |
| `WIREGUARD_ALLOWED_IPS` | Default AllowedIPs for clients (default: `0.0.0.0/0`) |
| `WIREGUARD_HELPER` | Installed path of the root helper (default: `/usr/local/sbin/wgla-helper`) |

## API

All protected routes require the `api-key` header.

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/status` | No | System status |
| GET | `/ip` | No | Server public IP |
| GET | `/links` | Yes | List all interfaces |
| POST | `/link` | Yes | Create interface |
| GET | `/link/{name}` | Yes | Get interface details |
| PATCH | `/link/{name}` | Yes | Update interface |
| DELETE | `/link/{name}` | Yes | Delete interface |
| GET | `/link/{link}/peers` | Yes | List peers |
| POST | `/link/{link}/peers` | Yes | Create peer |
| PATCH | `/link/{link}/peer/{pubkey}` | Yes | Update peer |
| DELETE | `/link/{link}/peer/{pubkey}` | Yes | Delete peer |
| GET | `/link/{link}/peer/{pubkey}/config` | Yes | Get peer client config |

`{pubkey}` is the peer's public key in URL-safe base64 without padding (`+/` → `-_`, `=` removed).

Updating a peer (`PATCH /link/{link}/peer/{pubkey}`) accepts:

| Field | Effect |
|-------|--------|
| `ip` | Moves the peer to another address in the link subnet: server-side AllowedIPs and the client config's `Address` |
| `dns` | DNS in the peer's client config |
| `allowed_ips` | AllowedIPs (routes) in the peer's client config. The server side is unchanged |

When a link's `port`, `dns`, `keepalive` or `allowed_ips` change, the stored client configs of its peers are regenerated. Per-peer `dns`/`allowed_ips` overrides are kept.

Link responses include the OS `interface` the link runs as (`utunN` on macOS), and never the server's private key.

A link can't reuse another link's listen port or overlap its subnet, and can't be named after an existing network interface. Without `port`, a free random port is picked.

Errors are JSON `{"error": "..."}`: `403` for a missing or wrong API key (also when `API_KEY` is unset), `404` for an unknown link or peer, `409` for a conflict (existing link, port, subnet or interface name), `422` for invalid input, and `500` when a system command fails (the message includes its error output).

## CLI

```bash
php artisan wg:help              # Setup instructions
php artisan wg:status            # System status
php artisan wg:links             # List interfaces
php artisan wg:link {name}       # Show interface details
php artisan wg:link:create       # Create interface
php artisan wg:link:update       # Update interface
php artisan wg:link:delete       # Delete interface
php artisan wg:link:peers        # List peers
php artisan wg:peer:create       # Create peer
php artisan wg:peer:update       # Update peer (--ip, --dns, --allowed-ips)
php artisan wg:peer:delete       # Delete peer
php artisan wg:peer              # Show peer client config
```
