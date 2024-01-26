# WireGuard Laravel API.

WireGuard Laravel API (or, WGLA) is an attempt to make a simple CLI/HTTP WireGuard API.
Mostly, work in progress and not so actively maintained. Feel free to contribute via pull-request or to contact via Issues.

## Installation.

To install WireGuard HTTP API you will need:
- systemd
- wireguard-tools
- iptables
- composer
- curl
- sudo (read below)
- http server (recommended)
- acl (recommended)

First things first, clone the repository and install Laravel:
```bash
git clone git@github.com:brindleydata/wireguard-laravel-api.git wireguard
cd wireguard
composer install
```
Then, you will need to start the application. Use HTTP server, or Laravel's built-in `./artisan serve`.
You can get some information about it on the Laravel documentation.

## Configuration.

WGLA do not require any database and tries to be as stateless as it is possible.
But to intercommunicate with the WireGuard, you need to set the serving application user needed access rights.
If the application is run via HTTP server, usually it's a `http` or `www-data`.
If the application is run via Laravel's own `artisan serve`, then it will be the user that launched the command.

WGLA will need r/w access to the `/etc/wireguard` directory and ability to run `wg`, `iptables` and `curl`.
To achieve the needed without crushing root-wide access rights, you can use `acl`, e.g.:
```bash
setfacl  --recursive --modify u:http:rwx /etc/wireguard
```

To access `wg`, `ip` and `iptables`, WGLA utilize the `sudo`, so you need to allow it:
```bash
# /etc/sudoers.d/wgla
www-data ALL = (ALL) NOPASSWD: /usr/bin/wg
www-data ALL = (ALL) NOPASSWD: /usr/bin/wg-quick
www-data ALL = (ALL) NOPASSWD: /usr/bin/systemctl
www-data ALL = (ALL) NOPASSWD: /usr/sbin/ip
www-data ALL = (ALL) NOPASSWD: /usr/sbin/iptables
```

This may be achieved by other, more restrictive methods. But for now we have what we have, sorry.

### To Do.
- Rework CLI, it's broken.
- Tests.
- Minimize amount of used commands.
