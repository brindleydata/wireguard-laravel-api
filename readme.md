# WireGuard Laravel API.

WireGuard Laravel API (or, WGLA) is an attempt to make a simple CLI/HTTP WireGuard API.
Mostly, work in progress and not so actively maintained. Feel free to contribute via pull-request or to contact via Issues.

## Installation.

To install WireGuard HTTP API you will need:
- systemd *
- wireguard-tools
- nftables
- composer
- curl
- php-sodium (ext-sodium)
- sudo (read below)
- http server (recommended)
- acl (recommended)

* Since the current app version is highly oriented to use `systemd` and `nftables`. That's not truly necessary and can be changed by a minor intervention, although this manual and current codebase are systemd-oriented. In a perfect time / universe, this app will have no other dependencies except of the `wg` itself, but this time isn't now, unfortunately. I hope this thing is a subject to improve or change in the future.

Ok, get back to work! First things first, clone the repository and install Laravel:
```bash
git clone git@github.com:brindleydata/wireguard-laravel-api.git wireguard
cd wireguard
composer install
```

Generate needed keys. You will the API_KEY to communicate with it via HTTP. You can also set custom external service to detect your IP address:
```bash
echo IP_SERVICE="ifconfig.me/ip" >> .env
echo API_KEY=`head -c48 /dev/urandom | base64` >> .env
```

Then, you will need to start the application. Use HTTP server of your choice, this question is not covered in this manual. E.g., you can use Laravel's built-in `./artisan serve`.
Also, you can get some more information on the [Laravel documentation](https://laravel.com/docs/10.x#creating-a-laravel-project) website.

Enable IP forwarding:
```bash
if [[ "`cat /proc/sys/net/ipv4/ip_forward`" != "1" ]]; then
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    echo 'net.ipv4.ip_forward = 1' | sudo tee /usr/lib/sysctl.d/10-wgla.conf
    sudo sysctl --system
fi
```

Forwarding and NAT rules are managed automatically via nftables. Each WireGuard link gets its own nft table (`wg_{name}`) when forwarding or NAT is enabled. No manual firewall setup is required.

And, the installation part done. Assuming you used port 25420 to run the application, check if it's alive by poking the `/status` endpoint:
```bash
PORT=25420 curl localhost:$PORT/status
```

## API.

All protected routes require the `api-key` header matching the `API_KEY` from `.env`.

### Public routes

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/status` | System status (CPU, RAM, disk) |
| GET | `/ip` | Server public IP |

### Link routes (protected)

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/links` | List all WireGuard interfaces |
| GET | `/link/{name}` | Show interface details and peers |
| POST | `/link` | Create interface (`name`, `ip` required; `port`, `ifout`, `dns`, `keepalive`, `allowed_ips`, `forward`, `nat`, `up` optional) |
| PATCH | `/link/{name}` | Update interface (`address`, `port`, `ifout`, `dns`, `keepalive`, `allowed_ips`, `forward`, `nat`, `up` — all optional) |
| DELETE | `/link/{name}` | Delete interface |

### Peer routes (protected)

Peers are identified by their WireGuard public key. In URLs, the public key must be base64url-encoded: replace `+` with `-`, `/` with `_`, and strip trailing `=` padding.

| Method | Route | Description |
|--------|-------|-------------|
| GET | `/link/{link}/peers` | List all peers on an interface |
| POST | `/link/{link}/peers` | Create peer (`ip` optional — auto-assigned from subnet if omitted) |
| PATCH | `/link/{link}/peer/{pubkey}` | Update peer (`allowed_ips`, `dns` — both optional) |
| DELETE | `/link/{link}/peer/{pubkey}` | Delete peer by base64url-encoded public key |
| GET | `/link/{link}/peer/{pubkey}/config` | Get peer client config by base64url-encoded public key |

Example — create a peer with auto-assigned IP:
```bash
curl -X POST -H 'api-key: YOUR_KEY' http://localhost:25420/link/wg0/peers
```

Example — delete a peer:
```bash
# given a pubkey like "abc+def/ghi=", encode it for the URL
safe=$(echo "$pubkey" | tr '+/' '-_' | tr -d '=')
curl -X DELETE -H 'api-key: YOUR_KEY' "http://localhost:25420/link/wg0/peer/${safe}"
```

## CLI.

```bash
php artisan wg:status                          # system status
php artisan wg:links                           # list interfaces
php artisan wg:link:show {name}                # show interface details
php artisan wg:link:create {name} {ip/cidr}    # create interface
php artisan wg:link:update {name} [options]    # update interface settings (--up=false to stop, --up=true to start)
php artisan wg:link:delete {name}              # delete interface
php artisan wg:link:peers {name}               # list peers on interface
php artisan wg:peer:create {link} [--ip=]      # create peer (IP optional, auto-assigned if omitted)
php artisan wg:peer:update {link} {pubkey}     # update peer settings
php artisan wg:peer:delete {link} {pubkey}     # delete peer by public key
php artisan wg:peer {link} {pubkey}            # show peer client config
```

## Configuration.

WGLA do not require any database and tries to be as stateless as it is possible.
But to intercommunicate with the WireGuard, you need to set the serving application user needed access rights.
If the application is run via HTTP server, usually it's a `http` or `www-data`.
If the application is run via Laravel's own `artisan serve`, then it will be the user that launched the command.

WGLA will need r/w access to the `/etc/wireguard` directory and ability to run `wg`, `nft` and `curl`.
To achieve the needed without crushing root-wide access rights, you can use `acl`, e.g.:
```bash
# Allow WireGuard Laravel API to access WireGuard config directory
setfacl  --recursive --modify u:http:rwx /etc/wireguard
```

To access `wg`, `ip` and `nft`, WGLA utilize the `sudo`, so you need to allow it:
```bash
echo "# Allow WireGuard Laravel API to access WG and network utils

http ALL = (ALL) NOPASSWD: /usr/bin/wg
http ALL = (ALL) NOPASSWD: /usr/bin/wg-quick
http ALL = (ALL) NOPASSWD: /usr/bin/systemctl stop wg-quick@*
http ALL = (ALL) NOPASSWD: /usr/bin/systemctl start wg-quick@*
http ALL = (ALL) NOPASSWD: /usr/sbin/nft" | sudo tee /etc/sudoers.d/wgla
```

This may be achieved by other, more restrictive methods. But for now we have what we have, sorry.

### To Do.
- Rework CLI, it's broken.
- Tests.
- Minimize amount of used CLI commands.
