#!/bin/bash
#
# End-to-end checks on a real Linux host set up by `php artisan wg:install`: real WireGuard,
# systemd, nftables/iptables and sudo, the API served by the wgla service, a real handshake from
# a client in its own network namespace, forwarding + NAT to a third one.
#
# DISPOSABLE MACHINES ONLY (CI runners, throwaway VMs): it creates and deletes links, network
# namespaces and firewall rules, and changes the iptables FORWARD policy.
#
#   sudo WGLA_E2E=1 tests/e2e/linux.sh [app dir]
#
set -u

[ "${WGLA_E2E:-}" = 1 ] || { echo "Refusing to run without WGLA_E2E=1: this changes the firewall and network setup." >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo): it creates network namespaces." >&2; exit 2; }

APP=$(cd "${1:-/srv/wgla}" && pwd)
env_get() { sed -n "s/^$1=//p" "$APP/.env" | tail -n 1 | tr -d '"'; }
WEB=$(env_get WGLA_WEB_USER)
HELPER=$(env_get WIREGUARD_HELPER); HELPER=${HELPER:-/usr/local/sbin/wgla-helper}
API_KEY=$(env_get API_KEY)
PORT=$(env_get WGLA_SERVER_PORT)
case "$(env_get WGLA_SERVER_TLS)" in
    http) URL="http://$(env_get WGLA_SERVER_BIND):$PORT"; CURL_OPTS=() ;;
    cert) URL="https://127.0.0.1:$PORT"; CURL_OPTS=(-k) ;;
    *) echo "Needs a server set up with --tls=http or --tls=cert" >&2; exit 2 ;;
esac

ART=(sudo -u "$WEB" php "$APP/artisan")
PASS=0; FAIL=0; SKIP=0
# Run an artisan command as the web user; when it fails, show why on stderr (its output is often discarded)
cli() {
    local out status
    out=$("${ART[@]}" "$@" 2>&1); status=$?
    if [ "$status" -ne 0 ]; then
        echo "  ! php artisan $* failed ($status):" >&2
        printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fi
    printf '%s\n' "$out"
    return "$status"
}
step()  { echo; echo "=== $*"; }
check() { if eval "$2" >/dev/null 2>&1; then echo "  ok   $1"; PASS=$((PASS + 1)); else echo "  FAIL $1"; FAIL=$((FAIL + 1)); fi; }
peer_key() { sed -n 's/^Added peer //p'; }
safe() { echo -n "$1" | tr '+/' '-_' | tr -d '='; }
as_web() { sudo -u "$WEB" "$@"; }
api() { curl -s "${CURL_OPTS[@]}" -o /tmp/wgla-e2e-body -w '%{http_code}' -H "api-key: $API_KEY" -H 'Content-Type: application/json' "$@"; }

FORWARD_POLICY=$(iptables -S FORWARD 2>/dev/null | sed -n 's/^-P FORWARD //p')
FORWARD6_POLICY=$(ip6tables -S FORWARD 2>/dev/null | sed -n 's/^-P FORWARD //p')
cleanup() {
    for link in e2e0 e2e1 e2e2 e2e3; do "${ART[@]}" wg:link:delete "$link" > /dev/null 2>&1; done
    ip netns del e2e-client 2>/dev/null; ip netns del e2e-far 2>/dev/null
    ip link del e2e-h 2>/dev/null; ip link del e2e-fh 2>/dev/null
    [ -n "$FORWARD_POLICY" ] && iptables -P FORWARD "$FORWARD_POLICY"
    [ -n "$FORWARD6_POLICY" ] && ip6tables -P FORWARD "$FORWARD6_POLICY"
    rm -f /tmp/wgla-e2e-*
}
trap cleanup EXIT
cleanup
iptables -P FORWARD ACCEPT 2>/dev/null; ip6tables -P FORWARD ACCEPT 2>/dev/null

step "What $WEB can and can't do as root"
check "only the helper is allowed" "! as_web sudo -n cat /etc/shadow"
check "wg itself is not allowed" "! as_web sudo -n wg show"
check "wg-quick itself is not allowed" "! as_web sudo -n wg-quick up /tmp/x.conf"
check "the helper refuses a path as link name" "! as_web sudo -n $HELPER conf-read ../../etc/shadow"
printf '[Interface]\nAddress = 10.9.0.1/24\nPrivateKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nListenPort = 51899\nPostUp = touch /tmp/wgla-e2e-pwned\n' > /tmp/wgla-e2e-evil.conf
check "the helper refuses a config with a planted hook" "! as_web sudo -n $HELPER conf-write e2eevil < /tmp/wgla-e2e-evil.conf"
check "... so it never runs" "! as_web sudo -n $HELPER up e2eevil && [ ! -e /tmp/wgla-e2e-pwned ]"
# The app tells "no such link" (3) from a failure (anything else), so the status must survive sudo
check "a config that isn't there is exit status 3 through sudo" "as_web sudo -n $HELPER conf-read e2enone; [ \$? -eq 3 ]"
check "the API reports the helper ok" "[ \"\$(api $URL/status)\" = 200 ] && grep -q '\"state\":\"ok\"' /tmp/wgla-e2e-body"
check "/health is public and ok" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /dev/null -w '%{http_code}' $URL/health)\" = 200 ]"
check "/status needs the API key" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /dev/null -w '%{http_code}' $URL/status)\" = 403 ]"

step "A dual-stack link with forward + NAT, out to a third network"
ip netns add e2e-far
ip link add e2e-fh type veth peer name e2e-fn
ip link set e2e-fn netns e2e-far
ip addr add 10.98.0.1/24 dev e2e-fh; ip -6 addr add fd98::1/64 dev e2e-fh nodad; ip link set e2e-fh up
ip netns exec e2e-far sh -c 'ip addr add 10.98.0.2/24 dev e2e-fn; ip -6 addr add fd98::2/64 dev e2e-fn nodad; ip link set e2e-fn up; ip link set lo up'
cli wg:link:create e2e0 10.80.0.1/24 --address6=fd80::1/64 --port=51880 --forward=true --nat=true --ifout=e2e-fh > /dev/null
check "running as a systemd unit" "wg show interfaces | grep -qw e2e0 && systemctl is-active -q wg-quick@e2e0"
check "config is 0600 root" "[ \"\$(stat -c %a:%U /etc/wireguard/e2e0.conf)\" = 600:root ]"
check "hooks call the helper" "grep -qx 'PostUp = $HELPER firewall-up %i %i' /etc/wireguard/e2e0.conf"
check "nftables: forward rules" "nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" accept'"
check "nftables: NAT only for the VPN subnet" "nft list table inet wg_e2e0 | grep -q 'ip saddr 10.80.0.0/24 oifname \"e2e-fh\" masquerade'"
check "nftables: NAT66 only for the VPN prefix" "nft list table inet wg_e2e0 | grep -q 'ip6 saddr fd80::/64 oifname \"e2e-fh\" masquerade'"
check "IPv6 forwarding is on (wg:install)" "[ \"\$(sysctl -n net.ipv6.conf.all.forwarding)\" = 1 ]"

step "A peer, and a real handshake from a client namespace"
PEER=$(cli wg:peer:create e2e0 | peer_key)
CLIENT=/etc/wireguard/clients/e2e0/$(safe "$PEER").conf
check "peer live and saved" "wg show e2e0 allowed-ips | grep -q \"$PEER.*10.80.0.2/32\" && grep -q \"PublicKey = $PEER\" /etc/wireguard/e2e0.conf"
check "client config is 0600" "[ \"\$(stat -c %a \"$CLIENT\")\" = 600 ]"
check "the peer's IPv6 address mirrors its IPv4 one" "wg show e2e0 allowed-ips | grep -q \"$PEER.*10.80.0.2/32 fd80::2/128\" && grep -qx 'Address = 10.80.0.2/32, fd80::2/128' \"$CLIENT\""
ip netns add e2e-client
ip link add e2e-h type veth peer name e2e-c
ip link set e2e-c netns e2e-client
ip addr add 10.99.0.1/24 dev e2e-h; ip link set e2e-h up
ip netns exec e2e-client sh -c 'ip addr add 10.99.0.2/24 dev e2e-c; ip link set e2e-c up; ip link set lo up'
ip netns exec e2e-client ip link add e2ec0 type wireguard
# The client config minus wg-quick's own keys (Address, DNS), through a pipe: Ubuntu's AppArmor
# profiles only let wg and wg-quick open files under /etc/wireguard, so no `wg-quick strip` of a copy
grep -vE '^(Address|DNS) =' "$CLIENT" | sed 's/^Endpoint = .*/Endpoint = 10.99.0.1:51880/' \
    | ip netns exec e2e-client wg setconf e2ec0 /dev/stdin
ip netns exec e2e-client sh -c 'ip addr add 10.80.0.2/32 dev e2ec0; ip -6 addr add fd80::2/128 dev e2ec0 nodad; ip link set e2ec0 up
    ip route add 10.80.0.0/24 dev e2ec0; ip route add 10.98.0.0/24 dev e2ec0; ip -6 route add fd80::/64 dev e2ec0; ip -6 route add fd98::/64 dev e2ec0'
check "the client reaches the server through the tunnel" "ip netns exec e2e-client ping -c1 -W3 10.80.0.1"
check "and the far network (forward + NAT)" "ip netns exec e2e-client ping -c1 -W3 10.98.0.2"
check "over IPv6 too" "ip netns exec e2e-client ping -6 -c1 -W3 fd80::1"
check "and the far network over IPv6 (forward + NAT66)" "ip netns exec e2e-client ping -6 -c1 -W3 fd98::2"
check "the API shows the peer connected, from its endpoint, with traffic" "[ \"\$(api $URL/link/e2e0/peers)\" = 200 ] && grep -q '\"connected\":true' /tmp/wgla-e2e-body && grep -q '\"endpoint\":\"10.99.0.2:' /tmp/wgla-e2e-body && grep -q '\"transfer_rx\":[1-9]' /tmp/wgla-e2e-body"

step "A FORWARD DROP policy like Docker or ufw set"
# Docker and ufw bring iptables; a host without it has nothing that drops forwarded traffic
if command -v iptables > /dev/null; then
    iptables -P FORWARD DROP; ip6tables -P FORWARD DROP
    cli wg:link:update e2e0 --forward=false > /dev/null
    cli wg:link:update e2e0 --forward=true > /dev/null
    check "the helper added two tagged accepts to iptables and ip6tables" "[ \"\$(iptables -S FORWARD | grep -c wgla:e2e0)\" = 2 ] && [ \"\$(ip6tables -S FORWARD | grep -c wgla:e2e0)\" = 2 ]"
    check "forwarding works through the DROP policy" "ip netns exec e2e-client ping -c1 -W3 10.98.0.2"
    check "... over IPv6 too" "ip netns exec e2e-client ping -6 -c1 -W3 fd98::2"
    systemctl restart wg-quick@e2e0
    check "a restart (PostUp) restores them without duplicates" "[ \"\$(iptables -S FORWARD | grep -c wgla:e2e0)\" = 2 ] && [ \"\$(ip6tables -S FORWARD | grep -c wgla:e2e0)\" = 2 ]"
    check "the client reconnects to the restarted server" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.98.0.2 && break; done"
    cli wg:link:update e2e0 --forward=false > /dev/null
    check "turning forward off removes them" "! iptables -S FORWARD | grep -q wgla:e2e0 && ! ip6tables -S FORWARD | grep -q wgla:e2e0"
    iptables -P FORWARD ACCEPT; ip6tables -P FORWARD ACCEPT
else
    echo "  skip no iptables on this host"; SKIP=$((SKIP + 6))
fi

step "Peer names, a disabled peer, networks behind a peer, QR codes"
cli wg:peer:update e2e0 "$PEER" --name="e2e client" > /dev/null
check "a name is a comment wg-quick ignores" "grep -qx '# name = e2e client' /etc/wireguard/e2e0.conf && systemctl restart wg-quick@e2e0 && wg show e2e0 peers | grep -q \"$PEER\""
cli wg:peer:update e2e0 "$PEER" --enabled=false > /dev/null
check "a disabled peer is off the interface, commented out in the config" "! wg show e2e0 peers | grep -q \"$PEER\" && grep -qx '# \[Peer\] disabled' /etc/wireguard/e2e0.conf"
check "... so it can't connect" "! ip netns exec e2e-client ping -c1 -W2 10.80.0.1"
systemctl restart wg-quick@e2e0
check "... not even after a restart" "! wg show e2e0 peers | grep -q \"$PEER\""
cli wg:peer:update e2e0 "$PEER" --enabled=true > /dev/null
check "enabled again, it connects with the same client config" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done"
# The client is a branch router: a LAN behind it
ip netns exec e2e-client sh -c 'ip link add e2e-lan type dummy; ip addr add 192.168.77.1/24 dev e2e-lan; ip link set e2e-lan up'
cli wg:peer:update e2e0 "$PEER" --networks=192.168.77.0/24 > /dev/null
check "wg-quick routes the network behind the peer" "ip route show 192.168.77.0/24 | grep -q 'dev e2e0'"
# The restart forgot the client's endpoint: the server can only send once the client has (keepalive)
check "the branch reconnects to the restarted server" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done"
check "the server reaches that network through the peer" "ping -c1 -W3 192.168.77.1"
cli wg:peer:update e2e0 "$PEER" --networks= > /dev/null
check "removing it removes the route" "[ -z \"\$(ip route show 192.168.77.0/24)\" ]"
check "the client config as a QR code in the terminal" "cli wg:peer e2e0 \"$PEER\" --qr | grep -q '▀'"
check "... and from the API as SVG" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /tmp/wgla-e2e-qr -w '%{content_type}' -H \"api-key: $API_KEY\" $URL/link/e2e0/peer/\$(safe \"$PEER\")/qr)\" = image/svg+xml ] && grep -q '<svg' /tmp/wgla-e2e-qr"

step "Clashes"
check "the same port is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.81.0.1/24 --port=51880"
check "an overlapping subnet is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.80.0.129/25 --port=51881"
check "an overlapping IPv6 prefix is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.81.0.1/24 --port=51881 --address6=fd80::abcd/64"
check "nothing was written" "[ ! -e /etc/wireguard/e2e1.conf ]"

step "Peers on a stopped link"
cli wg:link:create e2e1 10.81.0.1/24 --port=51881 --up=false > /dev/null
P1=$(cli wg:peer:create e2e1 | peer_key)
check "the link is not running, the peer is saved" "! wg show interfaces | grep -qw e2e1 && grep -q \"PublicKey = $P1\" /etc/wireguard/e2e1.conf"
cli wg:link:update e2e1 --up=true > /dev/null
check "the peer is loaded when the link starts" "wg show e2e1 peers | grep -q \"$P1\""
cli wg:link:update e2e1 --up=false > /dev/null
systemctl enable wg-quick@e2e1 > /dev/null 2>&1
cli wg:link:delete e2e1 > /dev/null
check "deleting it also disables a leftover unit" "! systemctl is-enabled -q wg-quick@e2e1 && [ ! -e /etc/wireguard/e2e1.conf ]"

step "A config written by hand"
printf '[Interface]\nAddress = 10.83.0.1/24\nPrivateKey = %s\nListenPort = 51883\nMTU = 1380\n' "$(wg genkey)" > /etc/wireguard/e2e3.conf
chmod 600 /etc/wireguard/e2e3.conf
check "is listed and shown" "cli wg:links | grep -qw e2e3 && cli wg:link e2e3 | grep -q '10.83.0.1/24'"
check "but not changed: that would drop its MTU" "! \"\${ART[@]}\" wg:peer:create e2e3 && grep -qx 'MTU = 1380' /etc/wireguard/e2e3.conf"
cli wg:link:delete e2e3 > /dev/null
check "and can be deleted" "[ ! -e /etc/wireguard/e2e3.conf ]"

step "HTTP API ($URL)"
check "a link that isn't there -> 404" "[ \"\$(api $URL/link/e2enone)\" = 404 ]"
check "GET /link has the interface, no private key" "[ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"interface\":\"e2e0\"' /tmp/wgla-e2e-body && ! grep -q private_key /tmp/wgla-e2e-body"
check "POST /link -> 201" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e2\",\"ip\":\"10.82.0.1/24\",\"port\":51882}')\" = 201 ]"
check "a port clash -> 409" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e3\",\"ip\":\"10.83.0.1/24\",\"port\":51882}')\" = 409 ]"
check "a line break in dns -> 422" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e3\",\"ip\":\"10.83.0.1/24\",\"dns\":\"1.1.1.1\\\\nPostUp = id\"}')\" = 422 ]"
check "no API key -> 403" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /dev/null -w '%{http_code}' $URL/links)\" = 403 ]"
check "DELETE /link/e2e2 -> 200" "[ \"\$(api -X DELETE $URL/link/e2e2)\" = 200 ]"

step "Backup and restore"
printf 'correct horse battery staple\n' > /tmp/wgla-e2e-pass && chmod 644 /tmp/wgla-e2e-pass
KEY0=$(wg show e2e0 public-key)
check "a backup, as the web user, with no key in clear" "\"\${ART[@]}\" wg:backup - --passphrase-file=/tmp/wgla-e2e-pass > /tmp/wgla-e2e.backup && grep -q '\"format\": \"wgla-backup\"' /tmp/wgla-e2e.backup && ! grep -q PrivateKey /tmp/wgla-e2e.backup"
cli wg:link:delete e2e0 > /dev/null
check "the link is gone" "! wg show interfaces | grep -qw e2e0 && [ ! -e /etc/wireguard/e2e0.conf ]"
check "restore it" "\"\${ART[@]}\" wg:restore - --passphrase-file=/tmp/wgla-e2e-pass --existing=skip --yes --no-interaction < /tmp/wgla-e2e.backup"
check "same keys, running again" "[ \"\$(wg show e2e0 public-key)\" = \"$KEY0\" ] && systemctl is-active -q wg-quick@e2e0"
check "the client's existing config connects again" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done"
check "... over IPv6 too" "ip netns exec e2e-client ping -6 -c1 -W3 fd80::1"

step "The wgla shortcut (wg:install)"
check "wgla runs link commands as the web user" "wgla links | grep -qw e2e0 && wgla link e2e0 | grep -q 'Interface: e2e0'"
check "... and takes a backup passphrase through sudo" "WGLA_BACKUP_PASSPHRASE='correct horse battery staple' wgla backup - | grep -q '\"format\": \"wgla-backup\"'"
check "wgla help shows a command's options" "wgla help peer:create | grep -q -- '--networks'"

step "Delete everything"
cli wg:link:delete e2e0 > /dev/null
check "no e2e links, configs, units or rules left" "! wg show interfaces | grep -q e2e && [ -z \"\$(find /etc/wireguard -name 'e2e*.conf')\" ] && ! nft list tables | grep -q wg_e2e && ! iptables -S FORWARD | grep -q wgla:e2e && ! ip6tables -S FORWARD | grep -q wgla:e2e"

echo
echo "RESULT: $PASS passed, $FAIL failed, $SKIP skipped"
if [ "$FAIL" -ne 0 ]; then
    echo; echo "=== wg-quick journal (failed run)"
    journalctl -u 'wg-quick@e2e*' -n 60 --no-pager -o cat 2>&1 | sed 's/^/  | /'
fi
[ "$FAIL" -eq 0 ]
