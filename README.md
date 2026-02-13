# WireGuard Laravel API (WGLA)

Stateless REST API and CLI for managing WireGuard VPN interfaces and peers. Built on Laravel 12 / PHP 8.5+. No database — all state lives in WireGuard `.conf` files and the kernel module.

## Requirements

- PHP 8.5+ with the `sodium` extension
- `wireguard-tools` (`wg`, `wg-quick`)
- `nftables` (Linux) or `pfctl` (macOS)
- `curl`
- Passwordless `sudo` for the web server user (see [Sudoers Setup](#sudoers-setup))
- IP forwarding enabled (if using forward/NAT features)

## Quick Start

```bash
composer install
cp .env.example .env
php artisan key:generate

# Set your API key
echo "API_KEY=$(openssl rand -hex 32)" >> .env

# Show platform-specific setup instructions
php artisan wg:help

# Start the API
php artisan serve --port=25420
```

## Sudoers Setup

The app runs under an isolated web server user and requires passwordless `sudo` for WireGuard management, firewall rules, and config file operations. All coreutils are path-restricted to the WireGuard config directory.

Run `php artisan wg:help` to see the full setup guide for your platform, or use the configs below.

### Linux

Replace `www-data` with your web server user.

```
www-data ALL=(root) NOPASSWD: \
    /usr/bin/wg, \
    /usr/bin/wg-quick, \
    /usr/sbin/nft, \
    /usr/bin/systemctl enable wg-quick@*, \
    /usr/bin/systemctl disable wg-quick@*, \
    /usr/bin/systemctl start wg-quick@*, \
    /usr/bin/systemctl stop wg-quick@*, \
    /usr/bin/cat /etc/wireguard/*, \
    /usr/bin/test -f /etc/wireguard/*, \
    /usr/bin/ls /etc/wireguard, \
    /usr/bin/mkdir -p /etc/wireguard, \
    /usr/bin/mkdir -p /etc/wireguard/clients/*, \
    /usr/bin/cp /tmp/* /etc/wireguard/*, \
    /usr/bin/chmod 600 /etc/wireguard/*, \
    /usr/bin/rm -f /etc/wireguard/*, \
    /usr/bin/rm -rf /etc/wireguard/clients/*
```

Install to `/etc/sudoers.d/wireguard` (mode `440`) and validate with `sudo visudo -cf /etc/sudoers.d/wireguard`.

Enable IP forwarding:

```bash
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wireguard.conf
sudo sysctl --system
```

### macOS (Apple Silicon)

Replace `_www` with your web server user. For Intel Macs, substitute `/opt/homebrew` with `/usr/local`.

```
_www ALL=(root) NOPASSWD: \
    /opt/homebrew/bin/wg, \
    /opt/homebrew/bin/wg-quick, \
    /sbin/pfctl, \
    /bin/cat /opt/homebrew/etc/wireguard/*, \
    /usr/bin/test -f /opt/homebrew/etc/wireguard/*, \
    /bin/ls /opt/homebrew/etc/wireguard, \
    /bin/mkdir -p /opt/homebrew/etc/wireguard, \
    /bin/mkdir -p /opt/homebrew/etc/wireguard/clients/*, \
    /bin/cp /tmp/* /opt/homebrew/etc/wireguard/*, \
    /bin/chmod 600 /opt/homebrew/etc/wireguard/*, \
    /bin/rm -f /opt/homebrew/etc/wireguard/*, \
    /bin/rm -rf /opt/homebrew/etc/wireguard/clients/*
```

Set up pfctl anchors (one-time):

```bash
sudo bash -c 'cat >> /etc/pf.conf <<EOF

# WireGuard NAT anchors
nat-anchor "wg/*"
anchor "wg/*"
EOF'
sudo pfctl -f /etc/pf.conf
```

Enable IP forwarding: `sudo sysctl -w net.inet.ip.forwarding=1`

### Why These Permissions?

| Command | Purpose |
|---------|---------|
| `wg` | Query/configure WireGuard interfaces and peers at runtime |
| `wg-quick` | Bring interfaces up/down (macOS); used via `systemctl` on Linux |
| `nft` | Manage nftables forward/NAT chains per interface (Linux) |
| `pfctl` | Manage pf anchor rules for forward/NAT (macOS) |
| `systemctl` | Enable/start/stop/disable `wg-quick@*` units (Linux) |
| `cat` | Read `.conf` files from the WireGuard config directory |
| `test` | Check whether a `.conf` file exists |
| `ls` | List `.conf` files in the WireGuard config directory |
| `mkdir` | Create config directory and per-link client subdirectories |
| `cp` | Copy temp files into the config directory (atomic write pattern) |
| `chmod` | Set `0600` permissions on config files |
| `rm` | Delete config files and client config directories |

All file-management commands (`cat`, `test`, `ls`, `mkdir`, `cp`, `chmod`, `rm`) are restricted to the WireGuard config directory path in the sudoers rules.

## Configuration

All settings are in `.env` — see `.env.example`. Key options:

| Variable | Description |
|----------|-------------|
| `API_KEY` | Shared secret for API authentication (required) |
| `WIREGUARD_HOSTNAME` | Endpoint hostname for client configs (auto-detected if empty) |
| `WIREGUARD_DNS` | Default DNS for client configs (default: `8.8.8.8`) |
| `WIREGUARD_KEEPALIVE` | Default PersistentKeepalive seconds (default: `25`) |
| `WIREGUARD_ALLOWED_IPS` | Default AllowedIPs for clients (default: `0.0.0.0/0`) |

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
php artisan wg:peer:update       # Update peer
php artisan wg:peer:delete       # Delete peer
php artisan wg:peer              # Show peer client config
```
