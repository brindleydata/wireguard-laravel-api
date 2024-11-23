# WireGuard Laravel API.

WireGuard Laravel API (or, WGLA) is an attempt to make a simple CLI/HTTP WireGuard API.
Mostly, work in progress and not so actively maintained. Feel free to contribute via pull-request or to contact via Issues.

## Installation.

To install WireGuard HTTP API you will need:
- systemd *
- wireguard-tools
- iptables
- composer
- curl
- sudo (read below)
- http server (recommended)
- acl (recommended)

* Since the current app version is highly oriented to use `systemd` and `iptables`. That's not truly necessary and can be changed by a minor intervention, although this manual and current codebase are systemd-oriented. In a perfect time / universe, this app will have no other dependencies except of the `wg` itself, but this time isn't now, unfortunately. I hope this thing is a subject to improve or change in the future.

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

Prepare the firewall chains:
```bash
if [[ "`cat /proc/sys/net/ipv4/ip_forward`" != "1" ]]; then
    echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
    echo 'net.ipv4.ip_forward = 1' | sudo tee /usr/lib/sysctl.d/10-wgla.conf
    sudo sysctl --system
fi

sudo iptables -N WGLA-FORWARD
sudo iptables -A WGLA-FORWARD -j RETURN
sudo iptables -I FORWARD -j WGLA-FORWARD

sudo iptables -t nat -N WGLA-NAT
sudo iptables -t nat -A WGLA-NAT -j RETURN
sudo iptables -t nat -I POSTROUTING -j WGLA-NAT
```

You will need these chains after system restart, so read the manuals of your Linux distribution on how to persist this.

And, the installation part done. Assuming you used port 25420 to run the application, check if it's alive by poking the `/status` endpoint:
```bash
PORT=25420 curl localhost:$PORT/status
```

## Configuration.

WGLA do not require any database and tries to be as stateless as it is possible.
But to intercommunicate with the WireGuard, you need to set the serving application user needed access rights.
If the application is run via HTTP server, usually it's a `http` or `www-data`.
If the application is run via Laravel's own `artisan serve`, then it will be the user that launched the command.

WGLA will need r/w access to the `/etc/wireguard` directory and ability to run `wg`, `iptables` and `curl`.
To achieve the needed without crushing root-wide access rights, you can use `acl`, e.g.:
```bash
# Allow WireGuard Laravel API to access WireGuard config directory
setfacl  --recursive --modify u:http:rwx /etc/wireguard
```

To access `wg`, `ip` and `iptables`, WGLA utilize the `sudo`, so you need to allow it:
```bash
echo "# Allow WireGuard Laravel API to access WG and network utils

http ALL = (ALL) NOPASSWD: /usr/bin/wg
http ALL = (ALL) NOPASSWD: /usr/bin/wg-quick
http ALL = (ALL) NOPASSWD: /usr/bin/systemctl stop wg-quick@*
http ALL = (ALL) NOPASSWD: /usr/bin/systemctl start wg-quick@*
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -L WGLA-FORWARD
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -A WGLA-FORWARD
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -D WGLA-FORWARD
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -t nat -L WGLA-NAT
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -t nat -A WGLA-NAT
http ALL = (ALL) NOPASSWD: /usr/sbin/iptables -t nat -D WGLA-NAT" | sudo tee /etc/sudoers.d/wgla
```

This may be achieved by other, more restrictive methods. But for now we have what we have, sorry.

### To Do.
- Rework CLI, it's broken.
- Tests.
- Minimize amount of used CLI commands.
