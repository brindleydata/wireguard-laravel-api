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
# And around an update that never ended, to a release that works: `interrupt` kills one half way
# and runs wg:update again, which has to go back first and then update.
#
#   sudo WGLA_E2E=1 tests/e2e/update.sh before [app dir]
#   WGLA_E2E=1 tests/e2e/update.sh release <tag> working                        # as the checkout's owner
#   WGLA_E2E=1 tests/e2e/update.sh interrupt [app dir] [the release's commit]   # as the deploy user
#   sudo WGLA_E2E=1 tests/e2e/update.sh after [app dir] [the release's commit]
#
set -u

[ "${WGLA_E2E:-}" = 1 ] || { echo "Refusing to run without WGLA_E2E=1: this changes the firewall and network setup, and 'release' commits in the checkout it is in." >&2; exit 2; }

usage() { echo "Usage: $0 before|after|back|interrupt [app dir] [commit]  or  $0 release <tag> unhealthy|unparsable|working" >&2; exit 2; }

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
# The one phase that needs no server
if [ "$PHASE" = release ]; then release "${2:-}" "${3:-}"; exit; fi

if [ "$PHASE" = interrupt ]; then
    [ "$(id -u)" -ne 0 ] || { echo "Run 'interrupt' as the deploy user, without sudo: it runs wg:update." >&2; exit 2; }
else
    [ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo): it creates network namespaces." >&2; exit 2; }
fi

APP=$(cd "${2:-/srv/wgla}" && pwd)
EXPECTED=${3:-}
# What the `before` phase leaves for `after`: keys, the client's config, the link as it was
STATE=/tmp/wgla-update-e2e
BODY=$STATE/body
CONF=/etc/wireguard/upd0.conf

# A value from a .env file as Laravel's dotenv reads the usual lines (bin/wgla has the same):
# the last one for the key (`export` and spaces around = allowed), "double-quoted" (\" \\ \$
# undone), 'single-quoted' as it is, or unquoted up to a # comment. Empty when it isn't there.
env_value() {
    local raw
    raw=$(sed -n -E "s/^[[:space:]]*(export[[:space:]]+)?$1[[:space:]]*=[[:space:]]*//p" "$2" 2> /dev/null | tail -n 1)
    case $raw in
        \"*) printf '%s\n' "$raw" | sed -E 's/^"(([^"\\]|\\.)*)".*$/\1/; s/\\(.)/\1/g' ;;
        \'*) printf '%s\n' "$raw" | sed -E "s/^'([^']*)'.*$/\\1/" ;;
        *) printf '%s\n' "$raw" | sed -E 's/#.*$//; s/[[:space:]]+$//' ;;
    esac
}
env_get() { env_value "$1" "$APP/.env"; }
WEB=$(env_get WGLA_WEB_USER)
DEPLOY=$(stat -c %U "$APP")
HELPER=$(env_get WIREGUARD_HELPER); HELPER=${HELPER:-/usr/local/sbin/wgla-helper}
API_KEY=$(env_get API_KEY)
PORT=$(env_get WGLA_SERVER_PORT)
BIND=$(env_get WGLA_SERVER_BIND); case "$BIND" in *:*) BIND="[$BIND]" ;; esac # IPv6, in a URL
case "$(env_get WGLA_SERVER_TLS)" in
    http) URL="http://$BIND:$PORT"; CURL_OPTS=() ;;
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
health() { curl -s "${CURL_OPTS[@]}" -o /dev/null -w '%{http_code}' "$URL/health"; }
# git as the checkout's owner: root isn't, and git then refuses the repository
repo() { if [ "$(id -u)" -eq 0 ]; then sudo -u "$DEPLOY" git -C "$APP" "$@"; else git -C "$APP" "$@"; fi; }
version() { repo describe --tags --always --dirty; }
client_config() { cli wg:peer upd0 "$1" | sed -n '/^\[Interface\]/,$p'; }
# Whether the link has an endpoint of its own (`# endpoint = …` before [Interface]). One made by a
# version from before has none: its client configs get an endpoint detected whenever they're built.
own_endpoint() { sed '/^\[Interface\]/q' "$CONF" | grep -q '^# endpoint = '; }
# Two client configs are the same. Without an endpoint of the link's own, but for the Endpoint
# line: that is detected anew (on CI the runner's public IP, where the version before used its
# WIREGUARD_HOSTNAME), so it only has to be there, with the link's port.
same_client_config() {
    if own_endpoint; then
        cmp -s "$1" "$2"
    else
        grep -q '^Endpoint = .*:51885$' "$2" && cmp -s <(grep -v '^Endpoint = ' "$1") <(grep -v '^Endpoint = ' "$2")
    fi
}
# How the checks name that difference
endpoint_note() { own_endpoint || echo " (but for the Endpoint, detected anew: the link has none of its own)"; }
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
    # The link's details are root's to read
    if [ "$FAIL" -ne 0 ] && [ "$(id -u)" -eq 0 ]; then
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
    local allow_default allow_own
    allow_default=$(env_get WGLA_ALLOW_DEFAULT_ROUTE); allow_own=$(env_get WGLA_ALLOW_OWN_NETWORKS)
    check "the route policy is root's, as answered (false unless asked)" "[ \"\$(stat -c %U /etc/wgla/policy.conf)\" = root ] && grep -qx 'allow_default_route=${allow_default:-false}' /etc/wgla/policy.conf && grep -qx 'allow_own_networks=${allow_own:-false}' /etc/wgla/policy.conf"

    step "The link from before the update"
    check "still running: the update never restarted it" "[ \"\$(cat /sys/class/net/upd0/ifindex)\" = \"\$(cat $STATE/ifindex)\" ] && systemctl is-active -q wg-quick@upd0"
    check "with the key it had" "[ \"\$(wg show upd0 public-key)\" = \"\$(cat $STATE/pubkey)\" ]"
    check "its firewall rules are in place" "masquerades"
    check "the client is still connected, with the config it has" "ip netns exec upd-client ping -c1 -W3 10.85.0.1 && ip netns exec upd-client ping -6 -c1 -W3 fd85::1"
    client_config "$PEER" > "$STATE/client.after"
    check "the new version hands out the very same client config$(endpoint_note)" "[ -s $STATE/client.after ] && same_client_config $STATE/client.conf $STATE/client.after"
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
    check "it is handed the very same client config$(endpoint_note)" "[ -s $STATE/client.back ] && same_client_config $STATE/client.conf $STATE/client.back"
    NEW=$(cli wg:peer:create upd0 --name="after going back" | peer_key)
    check "a peer can be added" "[ -n \"$NEW\" ] && wg show upd0 peers | grep -qF \"$NEW\" && grep -qF \"PublicKey = $NEW\" $CONF"
    cli wg:peer:delete upd0 "$NEW" > /dev/null
    check "... and removed again" "[ -n \"$NEW\" ] && ! wg show upd0 peers | grep -qF \"$NEW\" && [ \"\$(grep -c 'PublicKey = ' $CONF)\" = 3 ]"

    result
}

# An update that never ended: wg:update, killed with its whole process group (SIGKILL, like a
# dropped SSH session, only harder: nothing gets to clean up), then run again. That run has to go
# back to where the first one started, then update to the release. As the deploy user, who runs
# updates; `after` then checks the server on the release.
interrupt() {
    local from to record tmp pid deadline status
    [ "$(id -un)" = "$DEPLOY" ] || { echo "Run 'interrupt' as $DEPLOY, who owns $APP and runs its updates." >&2; exit 2; }
    from=$(repo rev-parse HEAD)
    record=$(repo rev-parse --git-path wgla-update); case $record in /*) ;; *) record=$APP/$record ;; esac
    tmp=$(mktemp -d)

    step "wg:update from $(version), killed half way"
    # Without job control a background command leads no process group, so setsid makes it the
    # leader of a session of its own without forking: $! is the group to kill
    (cd "$APP" && exec setsid php artisan wg:update --yes) > "$tmp/killed" 2>&1 < /dev/null &
    pid=$!
    # Killed once the checkout is at the release and the second stage (--finish) has started:
    # the code is between two versions. Not while `git status` or `composer install` run, before
    # that: killed as they write, they can leave git's index.lock or a broken vendor/ behind,
    # which `php artisan wg:update` can't get past, and whether they do would be up to chance.
    deadline=$((SECONDS + 600))
    until [ "$(repo rev-parse HEAD)" != "$from" ] && pgrep -g "$pid" -f 'wg:update --finish' > /dev/null; do
        if ! kill -0 "$pid" 2> /dev/null || [ "$SECONDS" -ge "$deadline" ]; then break; fi
        sleep 0.1
    done
    kill -KILL -- "-$pid" 2> /dev/null
    wait "$pid" 2> /dev/null
    # What it runs as root (sudo) is no process of its user's to kill: that ends by itself
    for _ in $(seq 600); do pgrep -g "$pid" > /dev/null || break; sleep 0.1; done
    sed 's/^/  | /' "$tmp/killed"
    to=$(repo rev-parse HEAD)

    check "the checkout had moved to the release${EXPECTED:+ ($EXPECTED)}" "[ $to != $from ] && [ $to = ${EXPECTED:-$to} ]"
    check "... and the update's record says it didn't end" "grep -qF '\"from\":\"$from\",\"to\":\"$to\"' $record"

    step "wg:update again"
    (cd "$APP" && php artisan wg:update --yes) > "$tmp/next" 2>&1 < /dev/null; status=$?
    sed 's/^/  | /' "$tmp/next"
    check "it says the update didn't end, and goes back first" "grep -qF \"didn't end. Going back to\" $tmp/next"
    check "... to where it started, then on to the release" "[ \"\$(repo reflog -3 --format=%gs)\" = \"\$(printf 'checkout: moving from %s to %s\n' $from $to $to $from $from $to)\" ]"
    check "... where it ends: the record is gone" "[ $status = 0 ] && grep -qF 'Updated to ' $tmp/next && [ ! -e $record ]"
    check "the checkout is at the release, with no local changes" "[ \"\$(repo rev-parse HEAD)\" = $to ] && [ -z \"\$(repo status --porcelain --untracked-files=no)\" ]"
    check "the API is healthy" "[ \"\$(health)\" = 200 ]"
    rm -rf "$tmp"

    result
}

case "$PHASE" in
    before) before ;;
    after) after ;;
    back) back ;;
    interrupt) interrupt ;;
    *) usage ;;
esac
