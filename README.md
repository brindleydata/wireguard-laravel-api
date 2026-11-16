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

This needs PHP 8.5+ with the `sodium` extension, Composer and git. The installer adds the rest. For each step it checks the machine, shows the commands that would fix it, then runs them (with `sudo`), lets you run them yourself, or skips the step:

| Step | Sets up |
|------|---------|
| Packages | WireGuard tools, nftables, PHP extensions (`wireguard-go` and bash on macOS) |
| Web user | Default `www-data`. The API never runs as root |
| Ownership | The code is read-only for the web user, which can only write `storage/` |
| `.env` | `APP_KEY`, `API_KEY` |
| Forwarding | IPv4 and IPv6, kept across reboots[^ra] |
| pf anchors | macOS only |
| Root helper | Installed root-owned in `/usr/local/sbin` |
| sudo rule | One line, checked with `visudo` |
| Route policy | What peers may route that would take the server's own traffic: a default route, or networks with the server's own addresses. Neither by default (`--allow-default-route=`, `--allow-own-networks=`); the root helper enforces it |
| AppArmor | Ubuntu 26.04+: lets the `wg-quick` hooks run the helper |
| Firewall timer | Linux: every minute, puts back the forward/NAT rules of a link that another tool removed |
| `wgla` | The [CLI](#cli) shortcut in `/usr/local/bin` |
| API server | Octane + FrankenPHP as a systemd service, with Let's Encrypt, your own certificate, or plain HTTP behind a proxy, on any port. FrankenPHP's admin API takes local port 2019, or the next free one when something else has it (`--admin-port=`) |
| Health | The web user can use the helper, and the API answers |

[^ra]: Where the kernel itself learns the IPv6 route from router advertisements (`accept_ra = 1`), forwarding would make it drop them, so that interface gets `accept_ra = 2`. netplan/networkd and NetworkManager aren't affected.

Run it again any time: finished steps show ✓, so it doubles as a health check.

```bash
php artisan wg:install --print          # the commands as a script, to review or run yourself
php artisan wg:install --step=helper    # only some steps
php artisan wg:install --yes --user=www-data --forward=true \
    --tls=letsencrypt --domain=api.example.com --port=443    # unattended
```

On macOS the API runs as you, without a service: `php artisan octane:start --server=frankenphp --port=8000`.

## Update

```bash
wgla update                     # the latest release (vX.Y.Z tags)
wgla update --to=v1.4.0         # a specific release, also an older one
wgla update --branch=master     # a branch, for testing
```

It runs as the deploy user and shows the changelog and any change to the root helper, checks out the release, reinstalls what changed and reloads the API without dropping connections. It also brings FrankenPHP to its current release, and restarts the API (briefly) when that changed. If anything fails, it goes back to the previous version.

After deploying another way (`git pull`, rsync), run `wgla install`. It notices that the API runs old code and reloads it.

## CLI

`wgla <command>` runs `php artisan wg:<command>` as the user it belongs to: link and peer commands as the web user (like the API), `install` and `update` as the deploy user. `wgla` alone lists the commands, and `wgla help <command>` shows a command's options. The link and peer commands and `status` take `--json` and then print exactly what the API returns for the same thing; a failure is `{"error": "…", "code": "…"}` (the API's [error codes](#errors)) with a non-zero exit code. A public key can be given in either form, as `wg` prints it or as the API's URLs have it. In a checkout, `bin/wgla` also works without installing, e.g. on macOS for development. It then uses that project, the `php` on your `PATH`, the web user from `.env` (otherwise you), and the project's owner for `install` and `update`. Without an installed root helper, link and peer commands use the project's `bin/wgla-helper` through your own `sudo`, which asks for your password once.

```text
wgla status                              version, system, interfaces, root helper (fails when the helper isn't usable)
wgla links                               link names
wgla link wg0                            a link and its peers
wgla link:create wg0 10.0.0.1/24 --address6=auto --forward=true --nat=true --endpoint=vpn.example.com
wgla link:create pbx 10.0.42.1/24 --forward=true --nat=true --destinations=10.20.0.0/16,192.0.2.50    its peers get nowhere else
wgla link:update wg0 --port=51821 --up=false     (--address6=none: IPv4 only; --dns="": the default again)
wgla link:update wg0 --address=10.1.0.1/24 --move-peers    another subnet, peers keep their host number
wgla link:adopt wg0 --dry-run            what taking a config written by hand, or by an older API, under management would keep and drop
wgla link:adopt wg0 --forward=true --nat=true --destinations=10.20.0.0/16    ... and do it (the options of link:update, but address, port and up)
wgla link:repair wg0                     put its forward/NAT rules back, if another tool removed them
wgla link:rekey wg0                      new keys for the link itself; every client needs its new config
wgla link:delete wg0
wgla link:peers wg0                      peers: names, state, live stats
wgla peer:create wg0 --name=laptop --qr  the new client config, also as a QR code
wgla peer:create wg0 --public-key=<key>  a device that made its own keys (--preshared-key-file= for a PSK of its own)
wgla peer wg0 <pubkey> [--qr]            the peer, and its client config again
wgla peer:update wg0 <pubkey> --enabled=false    (--name --ip --networks --remote --dns --allowed-ips --keepalive)
wgla peer:rekey wg0 <pubkey>             new keys for a peer; its old client config stops working
wgla peer:delete wg0 <pubkey>
wgla backup [file|-]                     encrypted backup of every link
wgla restore <file|->
```

## API

Every route except `GET /health` needs the `api-key` header. `GET /health` says which app answers, so a client can check that a URL is one of these servers before it sends its key there. `{pubkey}` is the peer's public key in URL-safe base64 without padding (`+/` → `-_`, no `=`).

| Route | |
|-------|---|
| `GET /health` | `200` `{"status": "ok", "app": "wgla"}`, or `503` with `"status": "unavailable"`. Nothing else. Public |
| `GET /status` | Version, system stats, root helper state |
| `GET /ip` | The server's public IPv4 and IPv6 |
| `GET /interfaces` | The host's network interfaces, and the `default` one a link goes out through (for `ifout`) |
| `GET /links` | Link names |
| `POST /link` | `name`, `ip` (CIDR), and optionally `address6`, `port`, `ifout`, `mtu`, `dns`, `keepalive`, `allowed_ips`, `forward`, `nat`, `inbound`, `destinations`, `allow_default_route`, `allow_own_networks`, `endpoint`, `private_key`, `up` |
| `GET /link/{name}` | The link and its peers. `endpoint` is where its clients connect, `client` has the `dns`, `keepalive` and `allowed_ips` of its own (`null`: the default), `destinations` are the only networks it forwards and NATs to (`null`: anywhere), `firewall` is `ok` or `missing` for a running link with forward, NAT or destinations, and `managed` is `false` for one the app shows but doesn't change (a [config written by hand](#adopting-a-config), an interface something else started) |
| `PATCH /link/{name}` | Any of the above but `private_key`, with `address` instead of `ip`, and `move_peers` to move the peers along to another subnet. `null` removes `address6` and the `destinations` (anywhere again), takes the link's own `mtu`, `dns`, `keepalive` or `allowed_ips` out, back to the default, and detects the `endpoint` anew |
| `POST /link/{name}/adopt` | Takes a [config written by hand, or by an older API](#adopting-a-config), under management. `ifout`, `forward`, `nat`, `inbound`, `destinations`, `allowed_ips`, `dns`, `keepalive`, `mtu`, `endpoint`, `allow_default_route`, `allow_own_networks`, and `dry_run`. Returns the link as `GET /link/{name}` does, with what was done under `adoption` |
| `POST /link/{name}/repair` | Puts a running link's forward/NAT rules back in place |
| `POST /link/{name}/rekey` | A new key pair for the link, applied live. Every client config changes |
| `DELETE /link/{name}` | |
| `GET /link/{link}/peers` | Peers with `name`, `enabled`, `networks`, `client` (the `dns`, `keepalive` and `allowed_ips` of their own, `null` where they follow the link) and live stats: `endpoint`, `latest_handshake_at`, `connected` (a handshake within 3 minutes), `transfer_rx`, `transfer_tx`. The stats are `null` while the peer isn't on the interface |
| `GET /link/{link}/peer/{pubkey}` | One peer |
| `POST /link/{link}/peers` | Optionally `ip`, `name`, `networks`, `remote`, `dns`, `keepalive`, `allowed_ips`, `enabled`, and `public_key` (with `preshared_key`) for a device that made its own keys. Returns the keys and the client config |
| `PATCH /link/{link}/peer/{pubkey}` | `ip`, `name`, `enabled`, `networks`, `remote`, and the client config's `dns`, `allowed_ips` and `keepalive`. `null` removes a name, networks or the remote, and takes one of the peer's own client settings out, back to the link's |
| `POST /link/{link}/peer/{pubkey}/rekey` | New keys for the peer. Returns it under its new public key, with its new client config |
| `DELETE /link/{link}/peer/{pubkey}` | |
| `GET /link/{link}/peer/{pubkey}/config` | The client config, as it is now |
| `GET /link/{link}/peer/{pubkey}/qr` | The client config as a QR code (`image/svg+xml`), for the WireGuard apps. Not for a peer with keys of its own (`422`): its config has no private key |

### Errors

Every error is `{"error": "…", "code": "…"}`. The message is for people and may be reworded; the code is what a client goes by.

| Status | `code` | |
|--------|--------|---|
| `403` | `unauthorized` | No API key, or a wrong one |
| `404` | `link_not_found` | No link of that name |
| `404` | `peer_not_found` | The link is there, the peer is not |
| `404` | `route_not_found` | No such route. Nothing else answers `404`: a link or peer that isn't there always has its own code |
| `405` | `method_not_allowed` | |
| `409` | `conflict` | A port, subnet, name or route that is taken, or what the server's route policy doesn't allow |
| `409` | `unmanaged_config` | The link's config has what the app doesn't write, so it isn't changed. [Adopt it](#adopting-a-config) |
| `409` | `unmanaged_interface` | An interface something else started: shown, never changed |
| `409` | `already_managed` | `adopt` for a link the app manages already: nothing to do, change it with `PATCH` |
| `409` | `not_adoptable` | `adopt` for a config with something that can't be carried over. The message names it |
| `422` | `invalid_input` | An invalid value, a field the route doesn't know (with `errors` per field when a field has the wrong type), or a malformed link name or public key in a change |
| `429` | `rate_limited` | 10 wrong API keys from an address in a minute: the rest of that minute |
| `500` | `system_error` | The host failed to do what was asked, or couldn't be asked (the message says why). Never a link that "isn't there" |

A read of a link name or public key that can't be one (`GET /link/no.such.name`) is a plain `404` with `link_not_found` or `peer_not_found`. Anything else the framework refuses is `request_refused`.

### Links and peers

- **Addresses.** A link has an IPv4 subnet and optionally an IPv6 prefix: its address is a host in the subnet (not the network or broadcast address, and never a `/0`), and `address6` is an address such as `fd12:3456:789a::1/64`, `auto` for a random private /64, or `null` to remove it. A peer gets the next free IPv4 address unless you give one, and the same host number in the prefix (`10.0.0.5` → `fd12:3456:789a::5`). Moving a peer moves both. A link can grow or shrink around its peers; moving it to another subnet needs `move_peers`, which keeps every peer's host number there (`10.0.0.5` → `10.1.0.5`), and every client then needs its new config.
- **Peers** can have a `name`, a label of up to 64 characters. Names don't have to be unique, and peers are still addressed by public key. A disabled peer (`enabled: false`) is off the interface but keeps its keys, address and client config. In the link config it's a commented-out `[Peer]` section.
- **Networks behind a peer** (`networks`, site-to-site), such as a branch office LAN, are routed to that peer. They can't overlap the link's addresses, other peers or other links. A default route (`0.0.0.0/0`, `::/0`) and a network that covers an address the server uses itself (its own, or its gateway's) would take the server's own traffic: they need the link's `allow_default_route` or `allow_own_networks`, which a link can only turn on where the server's route policy (set by `wg:install`) allows it. The peer's client config needs `allowed_ips` for whatever it should reach, and the link needs `forward` for traffic between networks. Changing a peer's networks, or removing such a peer, restarts a running link, because wg-quick sets up the routes. Peers reconnect by themselves when they next send traffic or a keepalive.
- **A peer the server connects to** (`remote`, `host:port`), for when the other side has the public address and this server doesn't. The server then opens the connection itself and sends that peer a keepalive every 25 seconds. A name has to resolve when it is set, and again whenever the app starts or restarts the link: one that doesn't would keep the whole link down.
- **Where clients connect** (`endpoint`, a host or `host:port`) is a link's own setting, in its client configs. Without one it is found when the link is made (the machine's name if that is a domain name or an IP, otherwise its public IPv4) and kept, so a new IP or name never changes what existing clients connect to. Behind a port forward it can have a port of its own.
- **MTU.** A link can have an `mtu` of its own. It is set on the interface and written into its clients' configs; changing it restarts a running link.
- **New keys.** `rekey` gives a peer a new key pair and preshared key, in its place and with everything else it has. Its public key changes, and with it its URL. A link's `rekey` replaces its own key pair, live: its peers keep theirs, but every client needs its new config.
- **Keys of their own.** A peer can come with its public key (and preshared key), for a device that made its key pair itself: its private key never reaches the server. Its client config then has no `PrivateKey` line, and there is no QR code of it. A link can be created with its own `private_key`, to move it here.
- **No clashes.** Links can't share a listen port, overlap subnets or prefixes, or take the name of an existing interface. Without `port`, a free random one is picked.
- **Rules that went missing.** A link's forward/NAT rules, and those for its destinations, are installed when it starts. If another tool removes them (a ruleset reload that flushes everything, a firewall restart), the link reports `firewall: missing`, `repair` puts them back, and on Linux a timer does that by itself within a minute. Rules for other destinations than the link has now count as missing too.
- **Forwarding and NAT** are per link and cover both families. Into the tunnel go only replies to connections peers started, unless the link has `inbound` (site-to-site, where the far side starts connections too). On Linux each link has an nftables table, `inet wg_<link>`, and NAT only masquerades the link's own subnet and prefix. On macOS each link has a pf anchor, `wg/<link>`. Where Docker or ufw drop forwarded traffic, the helper adds tagged accepts to iptables and ip6tables. firewalld isn't handled.
- **Destinations.** By default a link forwards its peers' traffic anywhere, and NAT masquerades it to anywhere. Its peers hold their own keys, and can route whatever they like into the tunnel by changing `AllowedIPs` on their side: so a link that is only for some networks (a few PBXs, an office) should say so. `destinations` is a list of networks of either family (`"10.20.0.0/16, 2001:db8:a::/48"`, or a JSON array; a bare address is one host), and then traffic out of the tunnel is forwarded only to those, everything else from its peers is dropped, and NAT only applies to those. A family without a destination gets nowhere. This holds whether or not the link has `forward` or `nat`, and also between its own peers and for networks behind them: list the link's subnet or those networks to allow that. What a peer sends to the server itself, and replies to connections that came in for a peer, are not affected (on macOS those replies need `forward`). `null` is anywhere again; an empty list and `/0` are refused, because they could be taken for either. The rules are part of what `firewall` reports and what `repair` and the timer put back.
- **Client configs** are not stored: only each peer's private key is. A config is built when it is asked for, so it always has the link's current endpoint, port, addresses and settings. Three settings come from the nearest place that has them: the peer's own, else its link's, else the fixed default (DNS `8.8.8.8`, keepalive `25`, all traffic through the tunnel: `0.0.0.0/0`, plus `::/0` on a dual-stack link). A link's and a peer's own are kept in the link config, next to the peer's name.
- **A change the link doesn't start with is undone.** A new port, address or MTU, or networks behind a peer, restart a running link. If it then doesn't come up (the port is taken, wg-quick can't add a route), the previous config goes back, the link runs again as it did, and the request fails with the reason.
- **Configs written by hand.** Any config in the WireGuard directory is listed and shown, and can be deleted. One that only uses what the app writes too is managed like the app's own. One with more (`Table`, `DNS`, hooks of its own, a keepalive other than 25, comments) is never changed, because the app regenerates configs whole and would drop those: it is shown with `managed: false`, and changes answer `409` (`unmanaged_config`) and name what is in the way. Such a config can be [adopted](#adopting-a-config).
- **Interfaces something else started.** A WireGuard interface that runs without a config in the WireGuard directory (started by `wg-quick` from another path, `ip link`, another tool) is listed and shown as well. Nothing about it is changed, stopped or deleted here (`409`): a peer added to it would be gone at its next start.
- The server's private key is never returned, and listings don't show peers' preshared keys: those are in each peer's client config only.

### Adopting a config

`POST /link/{name}/adopt` (`wgla link:adopt <name>`) takes a config the app didn't write under its management, in place: one written by hand, or by the API before this one, whose configs have hooks that set up iptables and peers with a preshared key and a `/32` each.

- **Kept exactly:** the link's private key (so its public key), listen port and addresses, an MTU, and every peer with its public key, preshared key and allowed IPs (its tunnel address and the networks behind it). No client has to change anything.
- **Dropped:** what the app does itself. `PreUp`, `PostUp`, `PreDown` and `PostDown` hooks, comments, `SaveConfig`, and settings that only spell out wg-quick's default (`Table = auto`). The hooks are not read for what they did: the adopted link gets the `forward`, `nat` and `destinations` the request gives it, and none if it gives none (the answer warns of that). Old hooks that masqueraded only what went to some networks are what `destinations` is for.
- **Refused** (`409`, `not_adoptable`, naming what is in the way, never quoting it): what the app has no place for. `Table`, `DNS`, `FwMark`, a second address, a keepalive the server sends a peer, a peer's `Endpoint` that is no `host:port`, a setting wg-quick doesn't know. And a peer the app couldn't address: one without a `/32` of its own in the link's subnet, or, on a dual-stack link, without the IPv6 address its IPv4 one gives it. A peer's `Endpoint` with a port becomes its `remote`. Put such a line right by hand first.
- **Settings:** those of `PATCH /link/{name}` but `address`, `address6`, `port`, `up` and `move_peers`, which an adoption doesn't change. Without `endpoint` it is detected as for a new link, without `ifout` it is the default route's.
- **Peers' private keys** are not in a link config. If the older API left a client config per peer in the link's client directory (`clients/<link>/<address>.conf`), their keys are taken over by public key, so those peers have a complete client config and QR code. Every other peer is one with a [key of its own](#links-and-peers): its config comes without `PrivateKey`. `adoption.keys` lists the public keys of each kind: `stored`, `imported`, `own`. The old files are left as they are.
- **A running link restarts.** It stops with its own config still in place, so its own `PostDown` takes down what its `PostUp` set up, then starts with the new one and the app's rules. If it doesn't come up, the previous config goes back and the link runs again as it did, and the request fails with the reason (`500`). A stopped link stays stopped. One that still runs after its `wg-quick@<name>` unit was stopped was started another way, and isn't adopted (`409`).
- **The config is what is adopted.** Where the running interface differs from it (a peer added or taken off with `wg set` and never saved), the restart makes it the config again, as any restart would, and `adoption.warnings` names those peers: look at a dry run first. The exception is a config with `SaveConfig = true`, which wg-quick writes from the interface when the link stops: for such a running link the interface has the peers that are adopted, and where they were last seen (`Endpoint`) is dropped.
- **`dry_run`** checks everything the real call would (that `ifout` exists, the `endpoint`, `allowed_ips` and `destinations`, port and subnet clashes with other links, what its peers route, that the root helper takes the new config) and answers the same way, with the link as it would be, but changes nothing.
- **Asked again** for a link that is managed, with or without `dry_run`, it answers `409` with `already_managed`, and doesn't apply the settings: use `PATCH`.

```json
{
  "name": "pbx", "managed": true, "up": true, "listen_port": 62990, "forward": true, "nat": true, "destinations": "10.20.0.0/16", "...": "as GET /link/{name}",
  "adoption": {
    "dry_run": false,
    "restarts": true,
    "kept": {"public_key": "…", "listen_port": 62990, "address": "10.0.42.1/24", "address6": null, "peers": 100},
    "dropped": {"PostUp": 1, "PostDown": 1},
    "applied": {"ifout": "eth0", "forward": true, "nat": true, "inbound": false, "destinations": "10.20.0.0/16", "endpoint": "vpn.example.com", "mtu": null, "dns": null, "keepalive": null, "allowed_ips": null, "allow_default_route": false, "allow_own_networks": false},
    "keys": {"stored": [], "imported": ["<public key>", "…"], "own": ["<public key>", "…"]},
    "warnings": []
  }
}
```

`dropped` counts lines by key and never quotes them, as a line of a config may hold a secret.

## Backup and restore

```bash
wgla backup [file|-]
wgla restore <file|->
```

A backup holds every link with its keys and its peers' private keys, encrypted with your passphrase (Argon2id + libsodium). Pass the passphrase with `--passphrase-file=` or `WGLA_BACKUP_PASSPHRASE`, or type it when asked. A restore checks everything before it changes anything. An existing link is skipped or replaced (asked, or `--existing=skip|replace`), and a link that can't be restored here can only be skipped: one that clashes with a link that stays, or a config written by hand with settings the app doesn't manage (`wgla backup` says so when it backs one up). A replaced link is only touched once the new config has passed every check. Links are rebuilt for the new server (its OS and outbound interface) and start again if they were running. Their clients keep connecting where they did, so point that name at the new server, or give the restore `--endpoint=` (every client then needs its new config). One that doesn't start stays, stopped, with its keys and client configs, and the restore says why. Backups are CLI only.

## Security

- Everything that needs root goes through `bin/wgla-helper`, installed root-owned. It's all the sudo rule allows: `www-data ALL=(root) NOPASSWD: /usr/local/sbin/wgla-helper`. The rule has no wildcards, so `sudo-rs` (Ubuntu 25.10+) takes it too.
- The helper takes a fixed set of commands and validates every argument. It only writes configs the app would generate, the only hooks it allows are its own firewall commands, and those only set up rules for the link's own interface.
- That holds for an adoption too. The helper replaces a config with the app's version of it only after checking that version like any other, and keeps the old one itself until the link runs: what goes back when it doesn't is what was there, never something the app hands in. Of the client configs an older API kept it prints public keys only, and it stores the private keys of the link's peers the way the app stores those it makes itself, which is where the API reads them from: that is what an adoption is asked to do.
- The app refuses to use a helper that differs from the bundled one, and `wg:install` reinstalls it.
- `wgla` is installed root-owned, with the app's path and users written into it. It only switches to the web user or the deploy user (with `sudo`) and runs `artisan`.
- Updates are never unattended, because they install code that runs as root.

## Configuration

In `.env` (see `.env.example`):

| Variable | |
|----------|---|
| `API_KEY` | The API secret. Without it, every route but `/health` returns `403` |
| `WIREGUARD_HELPER` | Where the root helper is installed (default `/usr/local/sbin/wgla-helper`) |
| `IP_SERVICE` | Where a new link's endpoint is looked up when the machine's name isn't a domain name (default `https://ifconfig.me/ip`) |

Where clients connect is each link's `endpoint`, not a server-wide setting.
