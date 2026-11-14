# WireGuard Laravel API

A REST API and CLI for WireGuard servers: links (interfaces), peers, client configs and QR codes, forwarding and NAT, site-to-site networks, over IPv4 and IPv6. There is no database: the state is the wg-quick configs and the live interfaces.

- The API runs as an unprivileged user. One small, strict root helper does the privileged work.
- A guided installer, an updater that rolls itself back on failure, and encrypted backups that restore on another server.
- Linux with systemd in production (CI installs and tests it on Ubuntu 24.04 and 26.04), macOS for development.

## Install

As the **deploy user**, the account that owns the code (not root), somewhere the web server user can reach:

```bash
sudo install -d -o "$USER" /srv/wgla
git clone https://github.com/brindleydata/wireguard-laravel-api.git /srv/wgla
cd /srv/wgla && composer install --no-dev --optimize-autoloader
php artisan wg:install
```

This needs PHP 8.5+ with `sodium`, `mbstring` and `dom`, Composer and git. The installer adds the rest. For each step it checks the machine, shows the commands that would fix it, then runs them (with `sudo`), lets you run them yourself, or skips the step:

| Step | Sets up |
|------|---------|
| Packages | WireGuard tools, nftables, PHP extensions (`wireguard-go` and bash on macOS) |
| Web user | Default `www-data`. The API never runs as root |
| Ownership | The code is read-only for the web user, which can only write `storage/` |
| `.env` | `APP_KEY`, `API_KEY`, the hostname clients connect to |
| Forwarding | IPv4 and IPv6, kept across reboots[^ra] |
| pf anchors | macOS only |
| Root helper | Installed root-owned in `/usr/local/sbin` |
| sudo rule | One line, checked with `visudo` |
| AppArmor | Ubuntu 26.04+: lets the `wg-quick` hooks run the helper |
| `wgla` | The [CLI](#cli) shortcut in `/usr/local/bin` |
| API server | Octane + FrankenPHP as a systemd service, with Let's Encrypt, your own certificate, or plain HTTP behind a proxy, on any port. FrankenPHP's admin API takes local port 2019, or the next free one when something else has it (`--admin-port=`) |
| Health | The web user can use the helper, and the API answers |

[^ra]: Where the kernel itself learns the IPv6 route from router advertisements (`accept_ra = 1`), forwarding would make it drop them, so that interface gets `accept_ra = 2`. netplan/networkd and NetworkManager aren't affected.

Run it again any time: finished steps show ✓, so it doubles as a health check.

```bash
php artisan wg:install --print          # the commands as a script, to review or run yourself
php artisan wg:install --step=helper    # only some steps
php artisan wg:install --yes --user=www-data --hostname=vpn.example.com --forward=true \
    --tls=letsencrypt --domain=api.example.com --port=443    # unattended
```

On macOS the API runs as you, without a service: `php artisan octane:start --server=frankenphp --port=8000`.

## Update

```bash
wgla update                     # the latest release (vX.Y.Z tags)
wgla update --to=v1.4.0         # a specific release, also an older one
wgla update --branch=master     # a branch, for testing
```

It runs as the deploy user and shows the changelog and any change to the root helper, checks out the release, reinstalls what changed and reloads the API without dropping connections. It also fetches the current FrankenPHP release each time, and restarts the API (briefly) when that changed. If anything fails, it goes back to the previous version.

After deploying another way (`git pull`, rsync), run `wgla install`. It notices that the API runs old code and reloads it.

## CLI

`wgla <command>` runs `php artisan wg:<command>` as the user it belongs to: link and peer commands as the web user (like the API), `install` and `update` as the deploy user. `wgla` alone lists the commands, and `wgla help <command>` shows a command's options. In a checkout, `bin/wgla` also works without installing, e.g. on macOS for development. It then uses that project, the `php` on your `PATH`, the web user from `.env` (otherwise you), and the project's owner for `install` and `update`. Without an installed root helper, link and peer commands use the project's `bin/wgla-helper` through your own `sudo`, which asks for your password once.

```text
wgla status                              version, system, root helper
wgla links                               link names
wgla link wg0                            a link and its peers
wgla link:create wg0 10.0.0.1/24 --address6=auto --forward=true --nat=true
wgla link:update wg0 --port=51821 --up=false     (--address6=none: IPv4 only; --dns="": the default again)
wgla link:update wg0 --address=10.1.0.1/24 --move-peers    another subnet, peers keep their host number
wgla link:delete wg0
wgla link:peers wg0                      peers: names, state, live stats
wgla peer:create wg0 --name=laptop --qr  the new client config, also as a QR code
wgla peer wg0 <pubkey> [--qr]            the client config again
wgla peer:update wg0 <pubkey> --enabled=false    (--name --ip --networks --dns --allowed-ips --keepalive)
wgla peer:delete wg0 <pubkey>
wgla backup [file|-]                     encrypted backup of every link
wgla restore <file|->
```

## API

Every route except `GET /health` needs the `api-key` header. `{pubkey}` is the peer's public key in URL-safe base64 without padding (`+/` → `-_`, no `=`).

| Route | |
|-------|---|
| `GET /health` | `200` or `503`, nothing else. Public |
| `GET /status` | Version, system stats, root helper state |
| `GET /ip` | The server's public IPv4 and IPv6 |
| `GET /links` | Link names |
| `POST /link` | `name`, `ip` (CIDR), and optionally `address6`, `port`, `ifout`, `dns`, `keepalive`, `allowed_ips`, `forward`, `nat`, `up` |
| `GET /link/{name}` | The link and its peers |
| `PATCH /link/{name}` | Any of the above, with `address` instead of `ip`, and `move_peers` to move the peers along to another subnet. `null` removes `address6`, and takes the link's own `dns`, `keepalive` or `allowed_ips` out, back to the default |
| `DELETE /link/{name}` | |
| `GET /link/{link}/peers` | Peers with `name`, `enabled`, `networks`, `client` (the `dns`, `keepalive` and `allowed_ips` of their own, `null` where they follow the link) and live stats: `endpoint`, `latest_handshake_at`, `connected` (a handshake within 3 minutes), `transfer_rx`, `transfer_tx`. The stats are `null` while the peer isn't on the interface |
| `POST /link/{link}/peers` | Optionally `ip`, `name`, `networks`. Returns the keys and the client config |
| `PATCH /link/{link}/peer/{pubkey}` | `ip`, `name`, `enabled`, `networks`, and the client config's `dns`, `allowed_ips` and `keepalive`. `null` removes a name or networks, and takes one of the peer's own client settings out, back to the link's |
| `DELETE /link/{link}/peer/{pubkey}` | |
| `GET /link/{link}/peer/{pubkey}/config` | The client config |
| `GET /link/{link}/peer/{pubkey}/qr` | The client config as a QR code (`image/svg+xml`), for the WireGuard apps |

Errors are `{"error": "…"}`: `403` (API key), `404`, `409` (port, subnet or name taken), `422` (invalid input; with `errors` per field when a field has the wrong type), `500` (a system command failed; the message says why).

### Links and peers

- **Addresses.** A link has an IPv4 subnet and optionally an IPv6 prefix: its address is a host in the subnet (not the network or broadcast address, and never a `/0`), and `address6` is an address such as `fd12:3456:789a::1/64`, `auto` for a random private /64, or `null` to remove it. A peer gets the next free IPv4 address unless you give one, and the same host number in the prefix (`10.0.0.5` → `fd12:3456:789a::5`). Moving a peer moves both. A link can grow or shrink around its peers; moving it to another subnet needs `move_peers`, which keeps every peer's host number there (`10.0.0.5` → `10.1.0.5`), and every client then needs its new config.
- **Peers** can have a `name`, a label of up to 64 characters. Names don't have to be unique, and peers are still addressed by public key. A disabled peer (`enabled: false`) is off the interface but keeps its keys, address and client config. In the link config it's a commented-out `[Peer]` section.
- **Networks behind a peer** (`networks`, site-to-site), such as a branch office LAN, are routed to that peer. They can't overlap the link's addresses, other peers or other links, and a default route is refused. The peer's client config needs `allowed_ips` for whatever it should reach, and the link needs `forward` for traffic between networks. Changing a peer's networks, or removing such a peer, restarts a running link, because wg-quick sets up the routes. Peers reconnect by themselves when they next send traffic or a keepalive.
- **No clashes.** Links can't share a listen port, overlap subnets or prefixes, or take the name of an existing interface. Without `port`, a free random one is picked.
- **Forwarding and NAT** are per link and cover both families. On Linux each link has an nftables table, `inet wg_<link>`, and NAT only masquerades the link's own subnet and prefix. On macOS each link has a pf anchor, `wg/<link>`. Where Docker or ufw drop forwarded traffic, the helper adds tagged accepts to iptables and ip6tables. firewalld isn't handled.
- **Client configs** are stored, and re-rendered when the link's port, addresses or client settings change. Three settings come from the nearest place that has them: the peer's own, else its link's, else the fixed default (DNS `8.8.8.8`, keepalive `25`, all traffic through the tunnel: `0.0.0.0/0`, plus `::/0` on a dual-stack link). A link's and a peer's own are kept in the link config, next to the peer's name.
- **A change the link doesn't start with is undone.** A new port or address, or networks behind a peer, restart a running link. If it then doesn't come up (the port is taken, wg-quick can't add a route), the previous config goes back, the link runs again as it did, and the request fails with the reason.
- **Configs written by hand.** Any config in the WireGuard directory is listed and shown, and can be deleted. One that only uses what the app writes too is managed like the app's own. One with more (`MTU`, `Table`, hooks of its own, a peer's `Endpoint`, comments) is never changed, because the app regenerates configs whole and would drop those: changes answer `409` and name what is in the way.
- The server's private key is never returned.

## Backup and restore

```bash
wgla backup [file|-]
wgla restore <file|->
```

A backup holds every link with its keys and client configs, encrypted with your passphrase (Argon2id + libsodium). Pass the passphrase with `--passphrase-file=` or `WGLA_BACKUP_PASSPHRASE`, or type it when asked. A restore checks everything before it changes anything. An existing link is skipped or replaced (asked, or `--existing=skip|replace`), and a link that can't be restored here can only be skipped: one that clashes with a link that stays, or a config written by hand with settings the app doesn't manage (`wgla backup` says so when it backs one up). A replaced link is only touched once the new config has passed every check. Links are rebuilt for the new server (its OS, outbound interface and hostname) and start again if they were running. One that doesn't start stays, stopped, with its keys and client configs, and the restore says why. Backups are CLI only.

## Security

- Everything that needs root goes through `bin/wgla-helper`, installed root-owned. It's all the sudo rule allows: `www-data ALL=(root) NOPASSWD: /usr/local/sbin/wgla-helper`. The rule has no wildcards, so `sudo-rs` (Ubuntu 25.10+) takes it too.
- The helper takes a fixed set of commands and validates every argument. It only writes configs the app would generate, the only hooks it allows are its own firewall commands, and those only set up rules for the link's own interface.
- The app refuses to use a helper that differs from the bundled one, and `wg:install` reinstalls it.
- `wgla` is installed root-owned, with the app's path and users written into it. It only switches to the web user or the deploy user (with `sudo`) and runs `artisan`.
- Updates are never unattended, because they install code that runs as root.

## Configuration

In `.env` (see `.env.example`):

| Variable | |
|----------|---|
| `API_KEY` | The API secret. Without it, every route but `/health` returns `403` |
| `WIREGUARD_HOSTNAME` | The endpoint in client configs. Default: the machine's FQDN, otherwise its public IPv4 |
| `WIREGUARD_HELPER` | Where the root helper is installed (default `/usr/local/sbin/wgla-helper`) |
