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
# A value from .env as dotenv reads the common cases: quoted, or unquoted up to a " #" comment
env_get() {
    local value
    value=$(sed -n "s/^$1=//p" "$APP/.env" | tail -n 1)
    case "$value" in
        \"*) value=${value#\"}; value=${value%%\"*} ;;
        \'*) value=${value#\'}; value=${value%%\'*} ;;
        *) value=${value%% #*}; value=${value%"${value##*[![:space:]]}"} ;;
    esac
    printf '%s' "$value"
}
WEB=$(env_get WGLA_WEB_USER)
HELPER=$(env_get WIREGUARD_HELPER); HELPER=${HELPER:-/usr/local/sbin/wgla-helper}
API_KEY=$(env_get API_KEY)
PORT=$(env_get WGLA_SERVER_PORT)
BIND=$(env_get WGLA_SERVER_BIND)
case "$BIND" in *:*) BIND_URL="[$BIND]" ;; *) BIND_URL=$BIND ;; esac
case "$(env_get WGLA_SERVER_TLS)" in
    http) URL="http://$BIND_URL:$PORT"; CURL_OPTS=() ;;
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
    ip link del e2e-h 2>/dev/null; ip link del e2e-fh 2>/dev/null; ip link del e2ex 2>/dev/null
    # What the hooks of the legacy config (adoption) set up, should a failed run have left it
    nft delete table ip e2e_legacy 2>/dev/null
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
check "... and says which app answers, before any key is sent" "curl -s ${CURL_OPTS[*]} $URL/health | grep -q '\"app\":\"wgla\"'"
check "/status needs the API key" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /dev/null -w '%{http_code}' $URL/status)\" = 403 ]"
if [ "$(env_get WGLA_SERVER_TLS)" = http ]; then
    # Behind a proxy: whatever Host header it passes on, and on the bind address only. (An IP in
    # Caddy's site address would only match the Host header, and it would listen everywhere.)
    check "the API answers any Host header a proxy passes on" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: api.example.com' $URL/health)\" = 200 ]"
    OTHER=$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
    if [ -n "$OTHER" ] && [ "$OTHER" != "$BIND" ]; then
        check "... and listens on $BIND only, not on $OTHER" "! curl -s --max-time 3 -o /dev/null http://$OTHER:$PORT/health"
    fi
fi

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
check "nftables: into the tunnel only replies, the rest dropped" "nft list table inet wg_e2e0 | grep -q 'oifname \"e2e0\" ct state established,related accept' && nft list table inet wg_e2e0 | grep -q 'oifname \"e2e0\" drop'"
check "nftables: NAT only for the VPN subnet" "nft list table inet wg_e2e0 | grep -q 'ip saddr 10.80.0.0/24 oifname \"e2e-fh\" masquerade'"
check "nftables: NAT66 only for the VPN prefix" "nft list table inet wg_e2e0 | grep -q 'ip6 saddr fd80::/64 oifname \"e2e-fh\" masquerade'"
check "IPv6 forwarding is on (wg:install)" "[ \"\$(sysctl -n net.ipv6.conf.all.forwarding)\" = 1 ]"

step "Firewall rules that another tool took away"
check "the repair timer runs (wg:install)" "systemctl is-active -q wgla-firewall.timer"
# Paused for these checks: it would put the rules back by itself, any second
systemctl stop wgla-firewall.timer
nft delete table inet wg_e2e0
check "the link says its rules are missing" "cli wg:link e2e0 | grep -q 'firewall rules are missing' && [ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"firewall\":\"missing\"' /tmp/wgla-e2e-body"
systemctl start wgla-firewall.service
check "what the timer runs puts them back" "nft list table inet wg_e2e0 | grep -q 'ip saddr 10.80.0.0/24 oifname \"e2e-fh\" masquerade' && [ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"firewall\":\"ok\"' /tmp/wgla-e2e-body"
nft delete table inet wg_e2e0
check "and so does wg:link:repair" "cli wg:link:repair e2e0 | grep -q 'are in place' && nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" accept'"
systemctl start wgla-firewall.timer

step "A peer, and a real handshake from a client namespace"
PEER=$(cli wg:peer:create e2e0 | peer_key)
KEYFILE=/etc/wireguard/clients/e2e0/$(safe "$PEER").conf
# Only the peer's private key is stored; its client config is built when asked for
CLIENT=/tmp/wgla-e2e-client.conf
cli wg:peer e2e0 "$PEER" | sed -n '/^\[Interface\]/,$p' > "$CLIENT"
check "peer live and saved" "wg show e2e0 allowed-ips | grep -q \"$PEER.*10.80.0.2/32\" && grep -q \"PublicKey = $PEER\" /etc/wireguard/e2e0.conf"
check "the stored key is 0600, and only the key" "[ \"\$(stat -c %a \"$KEYFILE\")\" = 600 ] && grep -q '^PrivateKey = ' \"$KEYFILE\" && ! grep -q Endpoint \"$KEYFILE\""
check "the client config has that key and this server as endpoint" "grep -qxF \"\$(grep '^PrivateKey = ' \"$KEYFILE\")\" \"$CLIENT\" && grep -q '^Endpoint = .*:51880\$' \"$CLIENT\""
check "the peer's IPv6 address mirrors its IPv4 one" "wg show e2e0 allowed-ips | grep -q \"$PEER.*10.80.0.2/32 fd80::2/128\" && grep -qx 'Address = 10.80.0.2/32, fd80::2/128' \"$CLIENT\""
ip netns add e2e-client
ip link add e2e-h type veth peer name e2e-c
ip link set e2e-c netns e2e-client
ip addr add 10.99.0.1/24 dev e2e-h; ip link set e2e-h up
ip netns exec e2e-client sh -c 'ip addr add 10.99.0.2/24 dev e2e-c; ip link set e2e-c up; ip link set lo up'
ip netns exec e2e-client ip link add e2ec0 type wireguard
# The client config minus wg-quick's own keys (Address, DNS, MTU), through a pipe: Ubuntu's AppArmor
# profiles only let wg and wg-quick open files under /etc/wireguard, so no `wg-quick strip` of a copy
grep -vE '^(Address|DNS|MTU) =' "$CLIENT" | sed 's/^Endpoint = .*/Endpoint = 10.99.0.1:51880/' \
    | ip netns exec e2e-client wg setconf e2ec0 /dev/stdin
ip netns exec e2e-client sh -c 'ip addr add 10.80.0.2/32 dev e2ec0; ip -6 addr add fd80::2/128 dev e2ec0 nodad; ip link set e2ec0 up
    ip route add 10.80.0.0/24 dev e2ec0; ip route add 10.98.0.0/24 dev e2ec0; ip -6 route add fd80::/64 dev e2ec0; ip -6 route add fd98::/64 dev e2ec0'
check "the client reaches the server through the tunnel" "ip netns exec e2e-client ping -c1 -W3 10.80.0.1"
check "and the far network (forward + NAT)" "ip netns exec e2e-client ping -c1 -W3 10.98.0.2"
check "over IPv6 too" "ip netns exec e2e-client ping -6 -c1 -W3 fd80::1"
check "and the far network over IPv6 (forward + NAT66)" "ip netns exec e2e-client ping -6 -c1 -W3 fd98::2"
check "the API shows the peer connected, from its endpoint, with traffic" "[ \"\$(api $URL/link/e2e0/peers)\" = 200 ] && grep -q '\"connected\":true' /tmp/wgla-e2e-body && grep -q '\"endpoint\":\"10.99.0.2:' /tmp/wgla-e2e-body && grep -q '\"transfer_rx\":[1-9]' /tmp/wgla-e2e-body"
# The far network starts a connection to the client: dropped, unless the link takes connections in
ip netns exec e2e-far ip route add 10.80.0.0/24 via 10.98.0.1
check "a connection from outside doesn't reach the peer (replies only)" "! ip netns exec e2e-far ping -c1 -W2 10.80.0.2"
cli wg:link:update e2e0 --inbound=true > /dev/null
check "... with --inbound=true it does" "ip netns exec e2e-far ping -c1 -W3 10.80.0.2 && nft list table inet wg_e2e0 | grep -q 'oifname \"e2e0\" accept'"
cli wg:link:update e2e0 --inbound=false > /dev/null
check "... and not again with --inbound=false" "! ip netns exec e2e-far ping -c1 -W2 10.80.0.2"

step "Destinations: a link that only forwards and NATs to the networks it is for"
# A second network beyond the far one, which the link is not for
ip netns exec e2e-far sh -c 'ip addr add 10.97.0.2/24 dev lo; ip -6 addr add fd97::2/64 dev lo'
ip route add 10.97.0.0/24 via 10.98.0.2; ip -6 route add fd97::/64 via fd98::2
ip netns exec e2e-client sh -c 'ip route add 10.97.0.0/24 dev e2ec0; ip -6 route add fd97::/64 dev e2ec0'
check "without destinations the peer reaches any network" "ip netns exec e2e-client ping -c1 -W3 10.97.0.2 && ip netns exec e2e-client ping -6 -c1 -W3 fd97::2"
cli wg:link:update e2e0 --destinations=10.98.0.0/24,fd98::/64 > /dev/null
check "nftables: a rule per destination, the rest out of the tunnel dropped" "nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" ip daddr 10.98.0.0/24 accept' && nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" ip6 daddr fd98::/64 accept' && nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" drop'"
check "nftables: NAT only to the destinations" "nft list table inet wg_e2e0 | grep -q 'ip saddr 10.80.0.0/24 ip daddr 10.98.0.0/24 oifname \"e2e-fh\" masquerade' && ! nft list table inet wg_e2e0 | grep -q 'ip saddr 10.80.0.0/24 oifname'"
check "the peer still reaches its destinations" "ip netns exec e2e-client ping -c1 -W3 10.98.0.2 && ip netns exec e2e-client ping -6 -c1 -W3 fd98::2"
check "... and nothing else, whatever it routes into the tunnel" "! ip netns exec e2e-client ping -c1 -W2 10.97.0.2 && ! ip netns exec e2e-client ping -6 -c1 -W2 fd97::2"
check "... but the server itself" "ip netns exec e2e-client ping -c1 -W3 10.80.0.1"
check "the API shows them, and the rules in place" "[ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"destinations\":\"10.98.0.0' /tmp/wgla-e2e-body && grep -q '\"firewall\":\"ok\"' /tmp/wgla-e2e-body"
systemctl stop wgla-firewall.timer
nft add rule inet wg_e2e0 forward iifname e2e0 ip daddr 10.97.0.0/24 accept
check "a rule for a destination the link doesn't have is not its rules" "[ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"firewall\":\"missing\"' /tmp/wgla-e2e-body"
systemctl start wgla-firewall.service
check "what the timer runs puts the link's own back" "! nft list table inet wg_e2e0 | grep -q 10.97.0.0 && [ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"firewall\":\"ok\"' /tmp/wgla-e2e-body"
systemctl start wgla-firewall.timer
systemctl restart wg-quick@e2e0
check "a restart (PostUp) installs them again" "nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" drop' && for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.98.0.2 && break; done && ! ip netns exec e2e-client ping -c1 -W2 10.97.0.2"
check "everything as a destination is refused: that is a link without any" "[ \"\$(api -X PATCH $URL/link/e2e0 -d '{\"destinations\":[\"0.0.0.0/0\"]}')\" = 422 ] && [ \"\$(api -X PATCH $URL/link/e2e0 -d '{\"destinations\":[]}')\" = 422 ]"
check "null takes them away: anywhere again" "[ \"\$(api -X PATCH $URL/link/e2e0 -d '{\"destinations\":null}')\" = 200 ] && grep -q '\"destinations\":null' /tmp/wgla-e2e-body && ip netns exec e2e-client ping -c1 -W3 10.97.0.2 && nft list table inet wg_e2e0 | grep -q 'iifname \"e2e0\" accept'"

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

step "Where clients connect, a link's new keys, a peer with a key of its own"
# The client namespace's interface on a client config (Address, DNS and MTU are wg-quick's, not wg's)
use_conf() { grep -vE '^(Address|DNS|MTU) =' "$1" | sed 's/^Endpoint = .*/Endpoint = 10.99.0.1:51880/' | ip netns exec e2e-client wg setconf e2ec0 /dev/stdin; }
cli wg:link:update e2e0 --endpoint=vpn.e2e.test:443 > /dev/null
check "a link's endpoint is in its clients' configs" "cli wg:peer e2e0 \"$PEER\" | grep -qx 'Endpoint = vpn.e2e.test:443'"
check "a remote whose name doesn't resolve is refused when it's set" "! \"\${ART[@]}\" wg:peer:create e2e0 --remote=nowhere.invalid:51820"
OLDKEY=$(wg show e2e0 public-key)
cli wg:link:rekey e2e0 > /dev/null
check "new keys for the link, live: the interface runs on with them" "[ \"\$(wg show e2e0 public-key)\" != \"$OLDKEY\" ] && grep -qF \"PrivateKey = \$(wg show e2e0 private-key)\" /etc/wireguard/e2e0.conf && systemctl is-active -q wg-quick@e2e0"
check "... a client with its old config can't connect any more" "! ip netns exec e2e-client ping -c1 -W2 10.80.0.1"
cli wg:peer e2e0 "$PEER" | sed -n '/^\[Interface\]/,$p' > "$CLIENT"
use_conf "$CLIENT"
check "... with its new one it does" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done"
# A device that makes its own keys: only its public key goes to the server
OWNKEY=$(wg genkey)
OWN=$(cli wg:peer:create e2e0 --public-key="$(echo "$OWNKEY" | wg pubkey)" --ip=10.80.0.9 | peer_key)
cli wg:peer e2e0 "$OWN" | sed -n '/^\[Interface\]/,$p' > /tmp/wgla-e2e-own.conf
check "a peer with a key of its own gets its config without the PrivateKey line, and none is kept" "[ -n \"$OWN\" ] && grep -q '^\[Peer\]' /tmp/wgla-e2e-own.conf && ! grep -q '^PrivateKey' /tmp/wgla-e2e-own.conf && [ ! -e \"/etc/wireguard/clients/e2e0/\$(safe \"$OWN\").conf\" ]"
sed -i "s|^\[Interface\]|[Interface]\nPrivateKey = $OWNKEY|" /tmp/wgla-e2e-own.conf
use_conf /tmp/wgla-e2e-own.conf
# The new address before the old one goes: without any IPv4 address the kernel drops the
# interface's routes (10.80.0.0/24 and the others, set up above)
ip netns exec e2e-client sh -c 'ip addr add 10.80.0.9/32 dev e2ec0; ip addr del 10.80.0.2/32 dev e2ec0'
check "... and connects with it" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done"
# Back to the first peer, for what follows
cli wg:peer:delete e2e0 "$OWN" > /dev/null
use_conf "$CLIENT"
ip netns exec e2e-client sh -c 'ip addr add 10.80.0.2/32 dev e2ec0; ip addr del 10.80.0.9/32 dev e2ec0'
check "... and the first peer connects again" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.80.0.1 && break; done && ip netns exec e2e-client ping -c1 -W2 fd80::1"

step "Clashes"
check "the same port is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.81.0.1/24 --port=51880"
check "an overlapping subnet is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.80.0.129/25 --port=51881"
check "an overlapping IPv6 prefix is refused" "! \"\${ART[@]}\" wg:link:create e2e1 10.81.0.1/24 --port=51881 --address6=fd80::abcd/64"
check "nothing was written" "[ ! -e /etc/wireguard/e2e1.conf ]"
OWN=$(ip -4 route get 192.0.2.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p')
if [ -n "$OWN" ]; then
    check "this server's own address can't be routed to a peer" "! \"\${ART[@]}\" wg:peer:create e2e0 --networks=$OWN/32"
else
    echo "  skip no IPv4 route out of this host"; SKIP=$((SKIP + 1))
fi

step "Peers on a stopped link; an MTU, a peer the server connects to, new keys"
cli wg:link:create e2e1 10.81.0.1/24 --port=51881 --up=false --mtu=1380 > /dev/null
P1=$(cli wg:peer:create e2e1 --remote=10.99.0.2:51999 | peer_key)
check "the link is not running, the peer is saved" "! wg show interfaces | grep -qw e2e1 && grep -q \"PublicKey = $P1\" /etc/wireguard/e2e1.conf"
cli wg:link:update e2e1 --up=true > /dev/null
check "the peer is loaded when the link starts" "wg show e2e1 peers | grep -q \"$P1\""
check "the interface has the link's MTU" "ip link show e2e1 | grep -q 'mtu 1380'"
check "the server connects to the peer, and keeps the path open" "wg show e2e1 endpoints | grep -q '10.99.0.2:51999' && [ \"\$(wg show e2e1 persistent-keepalive | awk '{print \$2}')\" = 25 ]"
P2=$(cli wg:peer:rekey e2e1 "$P1" | sed -n 's/^Rekeyed peer \([^ ]*\).*/\1/p')
check "new keys: the peer is there under its new public key only" "[ -n \"$P2\" ] && wg show e2e1 peers | grep -qF \"$P2\" && ! wg show e2e1 peers | grep -qF \"$P1\" && ! grep -qF \"$P1\" /etc/wireguard/e2e1.conf"
check "... still with where to connect to it" "wg show e2e1 endpoints | grep -q '10.99.0.2:51999'"
cli wg:link:update e2e1 --up=false > /dev/null
systemctl enable wg-quick@e2e1 > /dev/null 2>&1
cli wg:link:delete e2e1 > /dev/null
check "deleting it also disables a leftover unit" "! systemctl is-enabled -q wg-quick@e2e1 && [ ! -e /etc/wireguard/e2e1.conf ]"

step "A config written by hand"
printf '[Interface]\nAddress = 10.83.0.1/24\nPrivateKey = %s\nListenPort = 51883\nTable = off\n' "$(wg genkey)" > /etc/wireguard/e2e3.conf
chmod 600 /etc/wireguard/e2e3.conf
check "is listed and shown" "cli wg:links | grep -qw e2e3 && cli wg:link e2e3 | grep -q '10.83.0.1/24'"
check "but not changed: that would drop its Table setting" "! \"\${ART[@]}\" wg:peer:create e2e3 && grep -qx 'Table = off' /etc/wireguard/e2e3.conf"
cli wg:link:delete e2e3 > /dev/null
check "and can be deleted" "[ ! -e /etc/wireguard/e2e3.conf ]"

step "A config the API before this one wrote, adopted in place"
# As that API left a link: hooks of its own that masquerade what goes to the link's network,
# peers with a /32 each, a client config per peer it made the keys for. (Its hooks used iptables;
# these use nft, which wg-quick may run wherever AppArmor confines it.)
LKEY=$(wg genkey); LPUB=$(echo "$LKEY" | wg pubkey)
CKEY=$(wg genkey); CPUB=$(echo "$CKEY" | wg pubkey); CPSK=$(wg genpsk)
# As the API's JSON has a key: with its slashes escaped
CPUB_JSON=$(printf '%s' "$CPUB" | sed 's|/|\\/|g')
OPUB=$(wg genkey | wg pubkey)
{
    printf '[Interface]\nAddress = 10.83.0.1/24\nListenPort = 51883\nPrivateKey = %s\n' "$LKEY"
    printf '%s\n' "PostUp = nft add table ip e2e_legacy; nft 'add chain ip e2e_legacy post { type nat hook postrouting priority 100; }'; nft add rule ip e2e_legacy post ip daddr 10.98.0.0/24 oifname e2e-fh masquerade"
    printf '%s\n' 'PostDown = nft delete table ip e2e_legacy'
    printf '\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 10.83.0.2/32\n' "$CPUB" "$CPSK"
    printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = 10.83.0.3/32\n' "$OPUB"
} > /etc/wireguard/e2e3.conf
chmod 600 /etc/wireguard/e2e3.conf
cp /etc/wireguard/e2e3.conf /tmp/wgla-e2e-legacy.conf
mkdir -p /etc/wireguard/clients/e2e3
printf '[Interface]\nPrivateKey = %s\nAddress    = 10.83.0.2/32\nDNS        = 8.8.8.8\n\n[Peer]\nPublicKey    = %s\nPresharedKey = %s\nAllowedIPs   = 10.98.0.0/24\n' "$CKEY" "$LPUB" "$CPSK" > /etc/wireguard/clients/e2e3/10.83.0.2.conf
systemctl enable --now wg-quick@e2e3 > /dev/null 2>&1
# Its client, with the config it has had all along
ip netns exec e2e-client ip link add e2ec3 type wireguard
printf '[Interface]\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = 0.0.0.0/0\nEndpoint = 10.99.0.1:51883\nPersistentKeepalive = 1\n' "$CKEY" "$LPUB" "$CPSK" \
    | ip netns exec e2e-client wg setconf e2ec3 /dev/stdin
ip netns exec e2e-client sh -c 'ip addr add 10.83.0.2/32 dev e2ec3; ip link set e2ec3 up; ip route add 10.83.0.0/24 dev e2ec3; ip route add 10.98.0.2/32 dev e2ec3; ip route add 10.97.0.2/32 dev e2ec3'
check "it runs with its own hooks, and its client connects through it" "nft list table ip e2e_legacy | grep -q masquerade && ip netns exec e2e-client ping -c1 -W3 10.83.0.1 && ip netns exec e2e-client ping -c1 -W3 10.98.0.2"
check "it is shown as not managed, and not changed" "[ \"\$(api $URL/link/e2e3)\" = 200 ] && grep -q '\"managed\":false' /tmp/wgla-e2e-body && [ \"\$(api -X PATCH $URL/link/e2e3 -d '{\"nat\":true}')\" = 409 ] && grep -q '\"code\":\"unmanaged_config\"' /tmp/wgla-e2e-body"
check "a dry run says what would be kept and dropped" "cli wg:link:adopt e2e3 --dry-run --forward=true --nat=true --ifout=e2e-fh --destinations=10.98.0.0/24 > /tmp/wgla-e2e-dry && grep -q 'Dropped: PostUp ×1, PostDown ×1' /tmp/wgla-e2e-dry && grep -q '2 peers with their keys' /tmp/wgla-e2e-dry && grep -q \"Taken over: $CPUB\" /tmp/wgla-e2e-dry && grep -q \"Not here: $OPUB\" /tmp/wgla-e2e-dry"
check "... and changes nothing" "cmp -s /etc/wireguard/e2e3.conf /tmp/wgla-e2e-legacy.conf && nft list table ip e2e_legacy | grep -q masquerade && ! nft list table inet wg_e2e3 && ! ls /etc/wireguard/clients/e2e3 | grep -qv '^10.83.0.2.conf\$'"
check "what it can't carry over is refused by name" "sed -i 's/^ListenPort = 51883\$/ListenPort = 51883\\nTable = off/' /etc/wireguard/e2e3.conf && [ \"\$(api -X POST $URL/link/e2e3/adopt -d '{\"dry_run\":true}')\" = 409 ] && grep -q '\"code\":\"not_adoptable\"' /tmp/wgla-e2e-body && grep -q '(Table)' /tmp/wgla-e2e-body"
cp /tmp/wgla-e2e-legacy.conf /etc/wireguard/e2e3.conf
check "POST /link/{name}/adopt -> 200, managed, with whose keys were taken over" "[ \"\$(api -X POST $URL/link/e2e3/adopt -d '{\"forward\":true,\"nat\":true,\"ifout\":\"e2e-fh\",\"destinations\":[\"10.98.0.0/24\"]}')\" = 200 ] && grep -q '\"managed\":true' /tmp/wgla-e2e-body && grep -qF '\"imported\":[\"$CPUB_JSON\"]' /tmp/wgla-e2e-body && ! grep -qF \"$LKEY\" /tmp/wgla-e2e-body && ! grep -qF \"$CPSK\" /tmp/wgla-e2e-body"
check "the same link: key, port, address, peers and their preshared key" "[ \"\$(wg show e2e3 public-key)\" = \"$LPUB\" ] && [ \"\$(wg show e2e3 listen-port)\" = 51883 ] && ip -4 addr show dev e2e3 | grep -q '10.83.0.1/24' && wg show e2e3 allowed-ips | grep -q \"$CPUB.*10.83.0.2/32\" && wg show e2e3 allowed-ips | grep -q \"$OPUB.*10.83.0.3/32\" && wg show e2e3 preshared-keys | grep -qF \"$CPSK\""
check "its own PostDown took its rules along; the app's are in their place" "! nft list table ip e2e_legacy && nft list table inet wg_e2e3 | grep -q 'ip saddr 10.83.0.0/24 ip daddr 10.98.0.0/24 oifname \"e2e-fh\" masquerade'"
check "its config is the app's now, and the old one is not kept" "grep -qx 'PostUp = $HELPER firewall-up %i %i' /etc/wireguard/e2e3.conf && ! grep -q e2e_legacy /etc/wireguard/e2e3.conf && [ \"\$(stat -c %a:%U /etc/wireguard/e2e3.conf)\" = 600:root ] && [ ! -e /etc/wireguard/.e2e3.conf.before-adopt ] && systemctl is-active -q wg-quick@e2e3 && systemctl is-enabled -q wg-quick@e2e3"
check "its client reconnects with the config it has, and reaches the link's network" "for i in \$(seq 25); do ip netns exec e2e-client ping -c1 -W1 10.83.0.1 && break; done && ip netns exec e2e-client ping -c1 -W3 10.98.0.2"
check "... and no other (destinations)" "! ip netns exec e2e-client ping -c1 -W2 10.97.0.2"
check "the peer whose key the old API kept has a complete client config" "cli wg:peer e2e3 \"$CPUB\" | grep -qxF \"PrivateKey = $CKEY\" && cli wg:peer e2e3 \"$CPUB\" | grep -qx 'Address = 10.83.0.2/32'"
check "the other is a peer with a key of its own" "! cli wg:peer e2e3 \"$OPUB\" | grep -q '^PrivateKey'"
check "it is a link like any other now" "cli wg:peer:create e2e3 > /dev/null && [ \"\$(wg show e2e3 peers | wc -l)\" = 3 ]"
check "adopting it again -> 409 already_managed" "[ \"\$(api -X POST $URL/link/e2e3/adopt -d '{}')\" = 409 ] && grep -q '\"code\":\"already_managed\"' /tmp/wgla-e2e-body"
ip netns exec e2e-client ip link del e2ec3
cli wg:link:delete e2e3 > /dev/null
check "deleted like any other, with its old client configs" "[ ! -e /etc/wireguard/e2e3.conf ] && [ ! -e /etc/wireguard/clients/e2e3 ] && ! nft list table inet wg_e2e3"

step "A WireGuard interface that something else started"
ip link add e2ex type wireguard
check "is listed and shown" "cli wg:links | grep -qw e2ex && cli wg:link e2ex | grep -q 'Interface: e2ex'"
check "but a peer can't be added: nothing here would keep it" "! \"\${ART[@]}\" wg:peer:create e2ex && [ -z \"\$(wg show e2ex peers)\" ] && [ ! -e /etc/wireguard/clients/e2ex ]"
check "and it isn't 'deleted' while it runs on" "! \"\${ART[@]}\" wg:link:delete e2ex && [ \"\$(api -X DELETE $URL/link/e2ex)\" = 409 ] && ip link show e2ex"
ip link del e2ex

step "HTTP API ($URL)"
check "a link that isn't there -> 404 link_not_found" "[ \"\$(api $URL/link/e2enone)\" = 404 ] && grep -q '\"code\":\"link_not_found\"' /tmp/wgla-e2e-body"
check "a peer that isn't there -> 404 peer_not_found" "[ \"\$(api $URL/link/e2e0/peer/\$(safe \"\$(wg genkey | wg pubkey)\"))\" = 404 ] && grep -q '\"code\":\"peer_not_found\"' /tmp/wgla-e2e-body"
check "a route that isn't there -> 404 route_not_found" "[ \"\$(api $URL/nope)\" = 404 ] && grep -q '\"code\":\"route_not_found\"' /tmp/wgla-e2e-body"
check "a malformed name or key in a change -> 422, not 404" "[ \"\$(api -X DELETE $URL/link/no.such.link)\" = 422 ] && grep -q '\"code\":\"invalid_input\"' /tmp/wgla-e2e-body && [ \"\$(api -X DELETE $URL/link/e2e0/peer/not-a-key)\" = 422 ]"
check "GET /link has the interface, no private key" "[ \"\$(api $URL/link/e2e0)\" = 200 ] && grep -q '\"interface\":\"e2e0\"' /tmp/wgla-e2e-body && ! grep -q private_key /tmp/wgla-e2e-body"
check "POST /link -> 201" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e2\",\"ip\":\"10.82.0.1/24\",\"port\":51882}')\" = 201 ]"
check "a port clash -> 409" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e3\",\"ip\":\"10.83.0.1/24\",\"port\":51882}')\" = 409 ]"
check "a line break in dns -> 422" "[ \"\$(api -X POST $URL/link -d '{\"name\":\"e2e3\",\"ip\":\"10.83.0.1/24\",\"dns\":\"1.1.1.1\\\\nPostUp = id\"}')\" = 422 ]"
check "a misspelled field -> 422, not a silent 200" "[ \"\$(api -X PATCH $URL/link/e2e0 -d '{\"forwrad\":true}')\" = 422 ] && grep -q 'Unknown field: forwrad' /tmp/wgla-e2e-body"
check "no API key -> 403 unauthorized" "[ \"\$(curl -s ${CURL_OPTS[*]} -o /tmp/wgla-e2e-body -w '%{http_code}' $URL/links)\" = 403 ] && grep -q '\"code\":\"unauthorized\"' /tmp/wgla-e2e-body"
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
check "wgla --json prints what the API returns" "wgla link e2e0 --json | grep -q '\"name\": \"e2e0\"' && wgla links --json | grep -q '\"e2e0\"'"
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
