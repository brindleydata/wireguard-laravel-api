#!/bin/bash
#
# Checks around a real `php artisan wg:update` on a Linux host set up by `wg:install`: a link
# with a connected client, made by the version before, has to come through the update untouched,
# and the new version has to manage it like one of its own.
#
# DISPOSABLE MACHINES ONLY (CI runners, throwaway VMs), like linux.sh: it creates and deletes a
# link, a network namespace and firewall rules.
#
#   sudo WGLA_E2E=1 tests/e2e/update.sh before [app dir]            # on the version before
#   php artisan wg:update --yes                                     # as the deploy user
#   sudo WGLA_E2E=1 tests/e2e/update.sh after [app dir] [commit]    # on the new one
#
# Run it from a checkout of the new version: the old one may not have this script, and the
# `before` phase only uses commands every release has.
#
# And around an update that fails. The installed version is the one that has to find the way
# back, with code that can't be fixed any more once it is on a server. This needs a server
# whose origin is the checkout this script is in (as in CI), because the release is made there:
#
#   sudo WGLA_E2E=1 tests/e2e/update.sh before [app dir]
#   WGLA_E2E=1 tests/e2e/update.sh release <tag> unhealthy|unparsable|working   # as the checkout's owner
#   php artisan wg:update --yes                                     # has to fail
#   sudo WGLA_E2E=1 tests/e2e/update.sh back [app dir] [the release's commit]
#
set -u

[ "${WGLA_E2E:-}" = 1 ] || { echo "Refusing to run without WGLA_E2E=1: this changes the firewall and network setup, and 'release' commits in the checkout it is in." >&2; exit 2; }

usage() { echo "Usage: $0 before|after|back [app dir] [commit]  or  $0 release <tag> unhealthy|unparsable|working" >&2; exit 2; }

# A release that only exists here: this checkout plus one change, committed and tagged. Each
# starts from the newest commit that isn't one of these, so their changes don't add up. The
# commit is made on a detached HEAD: no branch moves.
release() {
    local tag=$1 kind=$2 base
    [ "$(id -u)" -ne 0 ] || { echo "Run 'release' as the owner of the checkout, without sudo: it commits there." >&2; exit 2; }
    case "$kind" in unhealthy | unparsable | working) ;; *) usage ;; esac
    [ -n "$tag" ] || usage
    cd "$(dirname "$0")/../.." || exit 2

    base=$(git log --format='%H %s' | grep -vE -m1 '^[0-9a-f]+ e2e release: ' | cut -d' ' -f1)
    git checkout --quiet --detach && git checkout --quiet "$base" -- . || exit 1
    case "$kind" in
        # Installs and is reloaded, then fails the health check: the way back starts after the
        # API ran it. (A route registered later takes the place of the one before.)
        unhealthy) printf "\nRoute::get('/health', fn () => response()->json(['status' => 'unavailable'], 503));\n" >> routes/api.php ;;
        # Doesn't get that far: Composer's package:discover can't boot it
        unparsable) echo 'this is not PHP' >> app/Providers/WireGuardServiceProvider.php ;;
        working) ;;
    esac
    git -c user.name=e2e -c user.email=e2e@localhost commit --quiet --allow-empty -am "e2e release: $kind" && git tag "$tag" || exit 1
    echo "Released $tag ($kind) as $(git rev-parse --short HEAD), from $(git log -1 --format='%h %s' "$base")"
}

PHASE=${1:-}
# The one phase that isn't for root, and needs no server
if [ "$PHASE" = release ]; then release "${2:-}" "${3:-}"; exit; fi

[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo): it creates network namespaces." >&2; exit 2; }

APP=$(cd "${2:-/srv/wgla}" && pwd)
EXPECTED=${3:-}
# What the `before` phase leaves for `after`: keys, the client's config, the link as it was
STATE=/tmp/wgla-update-e2e
BODY=$STATE/body
CONF=/etc/wireguard/upd0.conf

env_get() { sed -n "s/^$1=//p" "$APP/.env" | tail -n 1 | tr -d '"'; }
WEB=$(env_get WGLA_WEB_USER)
DEPLOY=$(stat -c %U "$APP")
HELPER=$(env_get WIREGUARD_HELPER); HELPER=${HELPER:-/usr/local/sbin/wgla-helper}
API_KEY=$(env_get API_KEY)
PORT=$(env_get WGLA_SERVER_PORT)
case "$(env_get WGLA_SERVER_TLS)" in
    http) URL="http://$(env_get WGLA_SERVER_BIND):$PORT"; CURL_OPTS=() ;;
    cert) URL="https://127.0.0.1:$PORT"; CURL_OPTS=(-k) ;;
    *) echo "Needs a server set up with --tls=http or --tls=cert" >&2; exit 2 ;;
esac

ART=(sudo -u "$WEB" php "$APP/artisan")
PASS=0; FAIL=0
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
api() { curl -s "${CURL_OPTS[@]}" -o "$BODY" -w '%{http_code}' -H "api-key: $API_KEY" -H 'Content-Type: application/json' "$@"; }
# git as the checkout's owner: root isn't, and git then refuses the repository
repo() { sudo -u "$DEPLOY" git -C "$APP" "$@"; }
version() { repo describe --tags --always --dirty; }
client_config() { cli wg:peer upd0 "$1" | sed -n '/^\[Interface\]/,$p'; }
reconnects() { for _ in $(seq 25); do ip netns exec upd-client ping -c1 -W1 10.85.0.1 && return 0; done; return 1; }
masquerades() { nft list table inet wg_upd0 | grep -q 'ip saddr 10.85.0.0/24 oifname .* masquerade'; }

teardown() {
    "${ART[@]}" wg:link:delete upd0 > /dev/null 2>&1
    ip netns del upd-client 2>/dev/null
    ip link del upd-h 2>/dev/null
    rm -rf "$STATE"
}

result() {
    echo
    echo "RESULT: $PASS passed, $FAIL failed"
    if [ "$FAIL" -ne 0 ]; then
        echo; echo "=== the link's config"
        sed -E 's/^(#? ?(PrivateKey|PresharedKey) = ).*/\1…/' "$CONF" 2>&1 | sed 's/^/  | /'
        echo; echo "=== wg-quick journal (failed run)"
        journalctl -u 'wg-quick@upd0' -n 40 --no-pager -o cat 2>&1 | sed 's/^/  | /'
    fi
    [ "$FAIL" -eq 0 ]
}

before() {
    teardown
    install -d -m 700 "$STATE"

    step "A link with a connected client, made by $(version)"
    # With what a config can hold: both families, forward + NAT (so hooks), an MTU and a DNS
    # server of the link's own, a named peer with a keepalive of its own, a disabled peer, and
    # one the server connects to
    cli wg:link:create upd0 10.85.0.1/24 --address6=fd85::1/64 --port=51885 --forward=true --nat=true --mtu=1380 --dns=9.9.9.9 > /dev/null
    PEER=$(cli wg:peer:create upd0 --name="from before" | peer_key)
    cli wg:peer:update upd0 "$PEER" --keepalive=5 > /dev/null
    OFF=$(cli wg:peer:create upd0 --name="switched off" | peer_key)
    cli wg:peer:update upd0 "$OFF" --enabled=false > /dev/null
    FAR=$(cli wg:peer:create upd0 --remote=10.97.0.9:51999 | peer_key)
    client_config "$PEER" > "$STATE/client.conf"

    ip netns add upd-client
    ip link add upd-h type veth peer name upd-c
    ip link set upd-c netns upd-client
    ip addr add 10.97.0.1/24 dev upd-h; ip link set upd-h up
    ip netns exec upd-client sh -c 'ip addr add 10.97.0.2/24 dev upd-c; ip link set upd-c up; ip link set lo up'
    ip netns exec upd-client ip link add updc0 type wireguard
    # The client config minus wg-quick's own keys, through a pipe (see linux.sh)
    grep -vE '^(Address|DNS|MTU) =' "$STATE/client.conf" | sed 's/^Endpoint = .*/Endpoint = 10.97.0.1:51885/' \
        | ip netns exec upd-client wg setconf updc0 /dev/stdin
    ip netns exec upd-client sh -c 'ip addr add 10.85.0.2/32 dev updc0; ip -6 addr add fd85::2/128 dev updc0 nodad; ip link set updc0 mtu 1380 up
        ip route add 10.85.0.0/24 dev updc0; ip -6 route add fd85::/64 dev updc0'

    check "three peers were made" "[ -n \"$PEER\" ] && [ -n \"$OFF\" ] && [ -n \"$FAR\" ] && [ \"\$(grep -c 'PublicKey = ' $CONF)\" = 3 ]"
    check "the link runs, with its rules" "systemctl is-active -q wg-quick@upd0 && masquerades"
    check "the client is connected" "ip netns exec upd-client ping -c1 -W3 10.85.0.1"
    check "... over IPv6 too" "ip netns exec upd-client ping -6 -c1 -W3 fd85::1"
    check "the API answers" "[ \"\$(api $URL/status)\" = 200 ] && grep -q '\"code\":\"' $BODY"

    printf '%s\n' "$PEER" > "$STATE/peer"; printf '%s\n' "$OFF" > "$STATE/off"; printf '%s\n' "$FAR" > "$STATE/far"
    grep -o '"code":"[^"]*"' "$BODY" > "$STATE/code"
    wg show upd0 public-key > "$STATE/pubkey"
    cat /sys/class/net/upd0/ifindex > "$STATE/ifindex"
    repo rev-parse HEAD > "$STATE/commit"

    result
}

after() {
    [ -s "$STATE/peer" ] || { echo "Nothing from a 'before' phase in $STATE: run that on the old version first." >&2; exit 2; }
    trap teardown EXIT
    PEER=$(cat "$STATE/peer"); OFF=$(cat "$STATE/off"); FAR=$(cat "$STATE/far")
    NOW=$(version)

    step "The update to $NOW"
    check "the checkout moved${EXPECTED:+ to $EXPECTED}" "[ \"\$(repo rev-parse HEAD)\" != \"\$(cat $STATE/commit)\" ] && [ \"\$(repo rev-parse HEAD)\" = \"${EXPECTED:-\$(repo rev-parse HEAD)}\" ]"
    check "... and has no local changes (the next update would refuse them)" "[ -z \"\$(repo status --porcelain --untracked-files=no)\" ]"
    check "the API says it runs $NOW" "[ \"\$(api $URL/status)\" = 200 ] && grep -qF '\"version\":\"$NOW\"' $BODY"
    check "... and was reloaded: its workers run other code than before" "grep -q '\"code\":\"' $BODY && ! grep -qF \"\$(cat $STATE/code)\" $BODY"
    check "the installed root helper is the new version's, and usable" "cmp -s $HELPER $APP/bin/wgla-helper && grep -q '\"state\":\"ok\"' $BODY"

    step "The link from before the update"
    check "still running: the update never restarted it" "[ \"\$(cat /sys/class/net/upd0/ifindex)\" = \"\$(cat $STATE/ifindex)\" ] && systemctl is-active -q wg-quick@upd0"
    check "with the key it had" "[ \"\$(wg show upd0 public-key)\" = \"\$(cat $STATE/pubkey)\" ]"
    check "its firewall rules are in place" "masquerades"
    check "the client is still connected, with the config it has" "ip netns exec upd-client ping -c1 -W3 10.85.0.1 && ip netns exec upd-client ping -6 -c1 -W3 fd85::1"
    client_config "$PEER" > "$STATE/client.after"
    check "the new version hands out the very same client config" "[ -s $STATE/client.after ] && cmp -s $STATE/client.conf $STATE/client.after"
    check "the API shows the link with its settings and rules" "[ \"\$(api $URL/link/upd0)\" = 200 ] && grep -q '\"mtu\":1380' $BODY && grep -q '\"dns\":\"9.9.9.9\"' $BODY && grep -q '\"firewall\":\"ok\"' $BODY"
    systemctl restart wg-quick@upd0
    check "it restarts from the config the old version wrote, hooks and all" "systemctl is-active -q wg-quick@upd0 && masquerades && ip link show upd0 | grep -q 'mtu 1380'"
    check "the client reconnects" "reconnects"

    step "Managed by the new version like one of its own"
    check "a change to a peer is taken: the config isn't read as written by hand" "cli wg:peer:update upd0 \"$PEER\" --name='after the update' && grep -qx '# name = after the update' $CONF"
    check "... and the rewrite lost nothing" "[ \"\$(grep -c 'PublicKey = ' $CONF)\" = 3 ] && grep -qx '# keepalive = 5' $CONF && grep -qx '# \[Peer\] disabled' $CONF && grep -qx 'Endpoint = 10.97.0.9:51999' $CONF && grep -qx 'MTU = 1380' $CONF && grep -qx '# dns = 9.9.9.9' $CONF"
    check "... on the interface either" "wg show upd0 peers | grep -qF \"$PEER\" && wg show upd0 peers | grep -qF \"$FAR\" && ! wg show upd0 peers | grep -qF \"$OFF\""
    NEW=$(cli wg:peer:create upd0 | peer_key)
    check "a new peer is live and saved" "[ -n \"$NEW\" ] && wg show upd0 peers | grep -qF \"$NEW\" && grep -qF \"PublicKey = $NEW\" $CONF"
    cli wg:peer:update upd0 "$OFF" --enabled=true > /dev/null
    check "the peer that was disabled is enabled" "wg show upd0 peers | grep -qF \"$OFF\""
    cli wg:link:update upd0 --mtu=1400 > /dev/null
    check "a link change that restarts it: new MTU, rules back" "ip link show upd0 | grep -q 'mtu 1400' && masquerades"
    check "the client reconnects once more" "reconnects"

    step "Delete it"
    cli wg:link:delete upd0 > /dev/null
    check "nothing of it is left" "! wg show interfaces | grep -qw upd0 && [ ! -e $CONF ] && [ ! -e /etc/wireguard/clients/upd0 ] && ! nft list tables | grep -q wg_upd0 && ! systemctl is-enabled -q wg-quick@upd0"

    result
}

# After an update that had to fail: the server is where it was, on the version that went back.
# The link and the state of the `before` phase stay, for the next update.
back() {
    [ -s "$STATE/peer" ] || { echo "Nothing from a 'before' phase in $STATE: run that first." >&2; exit 2; }
    PEER=$(cat "$STATE/peer")
    NOW=$(version)

    step "Back at $NOW after an update that failed"
    # Not an update that refused to start: the checkout was at the release, and left it again
    check "the update had moved to the release${EXPECTED:+ ($EXPECTED)}, and came back" "repo reflog -1 --format=%gs | grep -qx \"checkout: moving from ${EXPECTED:-[0-9a-f]*} to \$(cat $STATE/commit)\""
    check "the checkout is where it was" "[ \"\$(repo rev-parse HEAD)\" = \"\$(cat $STATE/commit)\" ]"
    check "... and has no local changes (the next update would refuse them)" "[ -z \"\$(repo status --porcelain --untracked-files=no)\" ]"
    check "the API is healthy" "[ \"\$(api $URL/health)\" = 200 ]"
    check "... and says it runs $NOW" "[ \"\$(api $URL/status)\" = 200 ] && grep -qF '\"version\":\"$NOW\"' $BODY"
    check "... with the code it ran before: nothing of the release is left" "grep -qF \"\$(cat $STATE/code)\" $BODY"
    check "the installed root helper is this version's, and usable" "cmp -s $HELPER $APP/bin/wgla-helper && grep -q '\"state\":\"ok\"' $BODY"

    step "The link, through the update and the way back"
    check "still running: nothing restarted it" "[ \"\$(cat /sys/class/net/upd0/ifindex)\" = \"\$(cat $STATE/ifindex)\" ] && systemctl is-active -q wg-quick@upd0"
    check "with the key it had" "[ \"\$(wg show upd0 public-key)\" = \"\$(cat $STATE/pubkey)\" ]"
    check "its firewall rules are in place" "masquerades"
    check "the client is still connected" "ip netns exec upd-client ping -c1 -W3 10.85.0.1 && ip netns exec upd-client ping -6 -c1 -W3 fd85::1"
    client_config "$PEER" > "$STATE/client.back"
    check "it is handed the very same client config" "[ -s $STATE/client.back ] && cmp -s $STATE/client.conf $STATE/client.back"
    NEW=$(cli wg:peer:create upd0 --name="after going back" | peer_key)
    check "a peer can be added" "[ -n \"$NEW\" ] && wg show upd0 peers | grep -qF \"$NEW\" && grep -qF \"PublicKey = $NEW\" $CONF"
    cli wg:peer:delete upd0 "$NEW" > /dev/null
    check "... and removed again" "[ -n \"$NEW\" ] && ! wg show upd0 peers | grep -qF \"$NEW\" && [ \"\$(grep -c 'PublicKey = ' $CONF)\" = 3 ]"

    result
}

case "$PHASE" in
    before) before ;;
    after) after ;;
    back) back ;;
    *) usage ;;
esac
