# WireGuard Laravel API (WGLA)

Stateless REST API and CLI for managing WireGuard VPN interfaces and peers. Built on Laravel 13 / PHP 8.5+. No database — all state lives in WireGuard `.conf` files and the kernel module.

## Requirements

- Linux with systemd (production; the installer automates Debian/Ubuntu via apt) or macOS with Homebrew (development)
- PHP 8.5+ with the `sodium`, `mbstring` and `dom` extensions, Composer and git
- `wireguard-tools`; on Linux `nftables` (`iptables` too if Docker or ufw manage the firewall); on macOS `wireguard-go`, Homebrew's bash and `pfctl`
- IP forwarding enabled (if using forward/NAT features)

`php artisan wg:install` checks all of these and installs what's missing.

## Setup

Clone the app as the **deploy user**: the account that owns the code and runs installs and updates. Put it outside home directories so the web server user can reach it, e.g. `/srv/wgla`. Then run the installer as that user, not as root:

```bash
sudo install -d -o "$USER" /srv/wgla
git clone https://github.com/brindleydata/wireguard-laravel-api.git /srv/wgla
cd /srv/wgla
composer install --no-dev --optimize-autoloader
php artisan wg:install
```

`wg:install` goes through the setup step by step. For each step it checks the machine, shows the exact commands that would fix what's missing, and then runs them (using `sudo` where needed), lets you run them yourself, or skips the step. The steps:

1. **Packages:** WireGuard tools, nftables, PHP extensions, git, Composer.
2. **Web server user:** default `www-data`. The API runs as this user, never as root.
3. **File ownership:** the code stays owned by the deploy user and read-only for the web user, and only `storage/` is writable by it. A compromised web process can't change the code it runs.
4. **`.env`:** generates `APP_KEY` and `API_KEY`, and sets the hostname clients connect to. `.env` is readable only by the web user's group.
5. **IP forwarding.**
6. **pf anchors** (macOS only).
7. **The root helper** (see below).
8. **The sudo rule:** one line, checked with `visudo` before it's installed.
9. **AppArmor** (Ubuntu 26.04 and later, which confine `wg-quick`): one rule in `/etc/apparmor.d/local/wg-quick` that lets the `PostUp`/`PostDown` hooks run the helper. Without it, links with forwarding or NAT can't start. The profile is compiled with the rule before it's reloaded, and a rule it rejects is rolled back.
10. **The API server:** Octane + FrankenPHP as a systemd service, which serves HTTPS itself. You choose how:
   - a Let's Encrypt certificate for a domain;
   - your own certificate files;
   - plain HTTP on a local port behind your own reverse proxy.

   You also choose the port. The installer explains the downsides of anything other than 443.
11. **Health check:** the web user can use the helper, and the API answers.

Run it again any time: finished steps just show ✓, so it doubles as a health check. Other ways to run it:

```bash
php artisan wg:install --print     # the same commands as a shell script, to review or run yourself
php artisan wg:install --yes --user=www-data --hostname=vpn.example.com --forward=true \
    --tls=letsencrypt --domain=api.example.com --port=443      # unattended (needs passwordless sudo)
php artisan wg:install --step=helper --step=health             # only some steps
```

On **macOS** (development) the API runs as you, and there's no service. Start it with `php artisan octane:start --server=frankenphp --port=8000` (or `php artisan serve`).

### The root helper

Everything that needs root goes through one small script, `bin/wgla-helper`, installed root-owned at `/usr/local/sbin/wgla-helper`. It's the only command the web server user may run with `sudo`:

```
www-data ALL=(root) NOPASSWD: /usr/local/sbin/wgla-helper
```

- **Strict arguments.** It accepts a fixed set of commands (`conf-write wg0`, `up wg0`, `peer-remove wg0 <key>`, …) and validates every argument.
- **Strict configs.** It only writes wg-quick configs that contain what the app generates. The only hooks allowed are calls back into the helper's own firewall commands. So the web user can manage links, but it can't run other commands, read other files or plant `PostUp` hooks as root.
- **Plain sudoers line.** It has no argument wildcards, so it works with classic `sudo` and with `sudo-rs`, which is the default on Ubuntu 25.10 and later.

The app refuses to use an installed helper that differs from the bundled one. That can happen after an update without a reinstall. `/status` and `wg:status` report the helper's state, and `wg:install` fixes it.

## Updating

```bash
cd /srv/wgla
php artisan wg:update                  # to the latest release (tags vX.Y.Z)
php artisan wg:update --to=v1.4.0      # to a specific release, also an older one
php artisan wg:update --branch=master  # follow a branch (for testing)
```

Run it as the deploy user. It refuses to overwrite local changes to the code. Before changing anything it shows the version change, the changelog and any change to the root helper, which runs as root, so review it. It then:

1. checks out the release and runs `composer install --no-dev`;
2. in a fresh process with the new code, reinstalls the helper if it changed, updates the sudo rule, the AppArmor rule and the service, reloads the API without dropping connections, and runs the health check.

If you deploy code another way, such as a plain `git pull` or rsync, run `php artisan wg:install` afterwards. It notices that the API still runs the old code and reloads it. (The API reports the code it booted with, and the wizard compares that with what's on disk.)

If any of that fails, it goes back to the previous version by itself. Updates are never unattended: an update installs code that runs as root. The release it ends up on is what `/status` reports as the version.

## Backup and restore

```bash
sudo -u www-data php artisan wg:backup                     # to storage/app/backups/wgla-<time>.backup (0600)
sudo -u www-data php artisan wg:backup - > server.backup   # or to stdout
sudo -u www-data php artisan wg:restore server.backup      # (- for stdin)
```

A backup holds every link, its keys and the stored client configs. It is encrypted with a passphrase you choose (Argon2id + libsodium), so it can only be restored with that passphrase, on this server or another one. Pass the passphrase with `--passphrase-file=` or `WGLA_BACKUP_PASSPHRASE`, or type it when asked. Backups exist only on the command line: the API never hands out private keys this way.

What a restore does:
- **Before changing anything,** it checks every link.
  - A link that already exists here is skipped or replaced, as you choose. Without a terminal, pass `--existing=skip|replace`; otherwise nothing is restored.
  - A link that would clash with one that stays (same port, overlapping subnet) can only be skipped.
- **Each link is rebuilt for this server.**
  - Links that were running start again.
  - If the outbound interface (e.g. `eth0`) doesn't exist here, the default route's interface is used, and the restore says so.
  - Client configs point at this server's `WIREGUARD_HOSTNAME`, keeping per-peer overrides. If the hostname changed, peers need their new config.

## Firewall notes

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

Every route except `/health` requires the `api-key` header.

| Method | Route | Auth | Description |
|--------|-------|------|-------------|
| GET | `/health` | No | `200 {"status":"ok"}` or `503 {"status":"unavailable"}`, for load balancers and monitoring |
| GET | `/status` | Yes | Version, system stats, root helper state |
| GET | `/ip` | Yes | Server public IP |
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

Peers of a running link include live stats from WireGuard. All of these are `null` while the link is down:

| Field | Meaning |
|-------|---------|
| `endpoint` | Where the peer last connected from (`ip:port`) |
| `latest_handshake_at` | Time of the last handshake (ISO 8601, UTC), `null` if it never connected |
| `connected` | Whether that handshake was within the last 3 minutes |
| `transfer_rx`, `transfer_tx` | Bytes received from and sent to the peer since the link started |

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
php artisan wg:help              # How to set up and update
php artisan wg:install           # Set up / check this server (as the deploy user)
php artisan wg:update            # Update to the latest release (as the deploy user)
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
php artisan wg:backup [file]     # Encrypted backup of every link
php artisan wg:restore {file}    # Restore from a backup
```

Except for `wg:help`, `wg:install` and `wg:update`, these run as the web server user (`sudo -u www-data php artisan …`), like the API. They refuse to run as anyone else once `wg:install` has set the user.
