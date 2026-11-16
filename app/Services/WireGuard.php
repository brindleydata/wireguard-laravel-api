<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\DTOs\PeerInfo;
use App\Exceptions\CommandFailedException;
use App\Exceptions\ConflictException;
use App\Exceptions\ErrorCode;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Services\Os\OsDriver;
use App\Validation\WireGuardValidator;
use Closure;
use InvalidArgumentException;

class WireGuard
{
    public function __construct(
        protected array $config,
        protected OsDriver $os,
        protected WireGuardValidator $validator,
        protected KeyManager $keys,
        protected ConfigBuilder $configBuilder,
        protected IpAllocator $ipAllocator,
        protected string $lockPath,
    ) {}

    // ─── Link operations ──────────────────────────────────────────────

    /**
     * Links with a .conf, plus running WireGuard interfaces that no .conf accounts for.
     */
    public function listLinks(): array
    {
        $links = $this->os->listConfigNames();
        $claimed = array_map(fn (string $link) => $this->os->resolveInterface($link), $links);
        $unmanaged = array_diff($this->runningInterfaces(), $claimed);

        return array_values(array_unique([...$links, ...$unmanaged]));
    }

    public function isRunning(string $name): bool
    {
        return $this->runtimeInterface($name) !== null;
    }

    /**
     * A link as it is now. For a running one with forward, NAT or destinations, `firewall` says
     * whether its rules are (still) in place: another tool may have flushed them.
     */
    public function getLink(string $name): ?InterfaceInfo
    {
        $iface = $this->runtimeInterface($name);
        $link = $this->loadLink($name, $iface);

        return $link !== null && $iface !== null && ($link->forward || $link->nat || $link->destinations !== null)
            ? $link->with(firewall: $this->os->firewallIntact($name, $iface) ? 'ok' : 'missing')
            : $link;
    }

    /**
     * getLink(), for callers to whom a link that isn't there is an error: a NotFoundException
     * that says so (`link_not_found`). A host that can't be asked is never "not there": that throws
     * a SystemException, as everywhere.
     */
    public function linkOrFail(string $name): InterfaceInfo
    {
        return $this->getLink($name) ?? throw NotFoundException::link($name);
    }

    /**
     * A peer of a link. The NotFoundException says which of the two isn't there (`link_not_found`,
     * `peer_not_found`); a malformed name or key is simply not there.
     */
    public function peerOrFail(string $link_name, string $pubkey): PeerInfo
    {
        $link = $this->loadLink($link_name, $this->runtimeInterface($link_name)) ?? throw NotFoundException::link($link_name);

        return $this->findPeer($link, KeyManager::normalize($pubkey)) ?? throw NotFoundException::peer($pubkey);
    }

    /**
     * Put a running link's forward/NAT rules back in place (as when it started). Harmless when
     * they are there; a stopped link gets its rules when it starts.
     */
    public function repairLink(string $name): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        return $this->withLock(function () use ($name) {
            $iface = $this->runtimeInterface($name);
            if ($iface === null && ! $this->os->configExists($name)) {
                throw NotFoundException::link($name);
            }
            if ($iface !== null && $this->os->configExists($name)) {
                $this->os->applyFirewall($name, $iface);
            }

            return $this->getLink($name) ?? throw NotFoundException::link($name);
        });
    }

    /**
     * New keys for a link (its own key pair), for when its private key got out. Applied live: no
     * restart. Its peers keep their keys and preshared keys, but every client config changes (the
     * server's public key is in it): all clients need their new one.
     */
    public function rekeyLink(string $name): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        return $this->withLock(function () use ($name) {
            $content = $this->managedConf($name);
            $iface = $this->runtimeInterface($name);
            $privkey = $this->keys->genkey();

            // The config first (rewritten from the live peers), then the interface: if that fails,
            // the config goes back (applyLive())
            $this->rewriteConf($name, preg_replace('/^PrivateKey\s*=.*$/m', "PrivateKey = {$privkey}", $content), $iface);
            if ($iface !== null) {
                $this->applyLive($name, $content, [[fn () => $this->os->setPrivateKey($iface, $privkey), null]]);
            }

            return $this->getLink($name) ?? throw NotFoundException::link($name);
        });
    }

    /**
     * @param  string|null  $address6  IPv6 address and prefix for a dual-stack link, or 'auto' for a
     *                                 random unique local /64
     * @param  bool  $inbound  forwarding into the tunnel takes connections that start outside (site-to-site), not only replies
     * @param  bool  $allow_default_route  its peers may route a default route, where the server's policy allows it
     * @param  bool  $allow_own_networks  its peers may route networks holding the server's own addresses, likewise
     * @param  string|null  $endpoint  where its clients connect (host, or host:port); null: detected now
     *                                 (ConfigBuilder::detectedHost()) and kept
     * @param  string|null  $private_key  its own key (moving a link here, or a peer of another server
     *                                    that knows its public key); null: a new one
     * @param  string|null  $destinations  the only networks traffic out of its tunnel is forwarded
     *                                     (and NATed) to, comma-separated; null: anywhere
     */
    public function createLink(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true, ?string $address6 = null, ?int $mtu = null, bool $inbound = false, bool $allow_default_route = false, bool $allow_own_networks = false, ?string $endpoint = null, ?string $private_key = null, ?string $destinations = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        $endpoint = $endpoint === null || $endpoint === '' ? null : $this->validator->endpoint($endpoint);
        $private_key = $private_key === null || $private_key === '' ? null : $this->validator->key($private_key, 'private key');

        $address = $this->validator->linkAddress(str_contains($ip, '/') ? $ip : "{$ip}/24");
        $address6 = $this->resolveAddress6($address6, $address);
        if ($mtu !== null) {
            $this->validator->validateMtu($mtu, $address6 !== null);
        }
        ['dns' => $dns, 'allowed_ips' => $allowed_ips, 'destinations' => $destinations] = $this->validateSettings(['dns' => $dns, 'keepalive' => $keepalive, 'allowed_ips' => $allowed_ips, 'ifout' => $ifout, 'destinations' => $destinations]);

        return $this->withLock(function () use ($name, $address, $address6, $port, $ifout, $dns, $keepalive, $allowed_ips, $forward, $nat, $up, $mtu, $inbound, $allow_default_route, $allow_own_networks, $endpoint, $private_key, $destinations) {
            if (in_array($name, $this->listLinks(), true)) {
                throw new ConflictException("Link already exists: {$name}");
            }
            $this->assertPolicyAllows($allow_default_route, $allow_own_networks);

            $system_interfaces = $this->os->networkInterfaces();
            if (in_array($name, $system_interfaces, true)) {
                throw new ConflictException("A network interface named {$name} already exists");
            }
            if ($ifout !== null && ! in_array($ifout, $system_interfaces, true)) {
                throw new InvalidArgumentException("Output interface does not exist: {$ifout}");
            }

            $ifout = $ifout ?? $this->os->defaultOutboundInterface();

            $others = $this->otherLinks($name);
            $port = $port ?? $this->freePort($others);
            $this->validator->validatePort($port);
            $this->assertNoClash($port, $address, $others, $address6);
            $privkey = $private_key ?? $this->keys->genkey();
            // Kept: a client config never points elsewhere behind its back
            $endpoint ??= $this->detectedEndpoint();

            $content = $this->configBuilder->buildConfFile($address, $privkey, $port, $ifout, [], $dns, $keepalive, $allowed_ips, $forward, $nat, $address6, $mtu, $inbound, $allow_default_route, $allow_own_networks, $endpoint, $destinations);
            $this->os->writeConfig($name, $content);

            if ($up) {
                try {
                    $this->os->startInterface($name);
                } catch (\Throwable $e) {
                    try {
                        $this->os->stopInterface($name);
                    } catch (\Throwable) {
                    }
                    $this->os->clearFirewall($name);
                    try {
                        $this->os->deleteConfig($name);
                    } catch (\Throwable) {
                        throw new SystemException("Link {$name} was created but did not start, and its config could not be removed again (delete the link): {$e->getMessage()}", 0, $e);
                    }

                    throw new SystemException("Failed to create link {$name}: {$e->getMessage()}", 0, $e);
                }
            }

            return $this->getLink($name) ?? throw new SystemException("Link {$name} was created but could not be read back.");
        });
    }

    public function deleteLink(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $this->withLock(function () use ($name) {
            $iface = $this->runtimeInterface($name);

            if (! $this->os->configExists($name)) {
                // Not there, or an interface that runs without a config: not this app's to stop
                throw $this->withoutConfig($name);
            }

            try {
                $this->os->stopInterface($name);
            } catch (CommandFailedException $e) {
                // Only a running link must stop; for a stopped one this just tidies up
                if ($iface !== null) {
                    throw $e;
                }
            }
            // PostDown normally removes the rules; this also covers hooks that no longer match
            $this->os->clearFirewall($name);

            // The config last: while it is there the link is, and a delete that failed halfway
            // can be asked for again
            $this->os->deleteClientConfigDir($name);
            $this->os->deleteConfig($name);
        });
    }

    /**
     * Change a link's settings. `dns`, `keepalive` and `allowed_ips` are the link's own client
     * settings: null (or '') removes one, so the fixed default applies again.
     *
     * A change that needs the link (re)started is undone when the link then doesn't start: the
     * previous config goes back and a link that was running runs again.
     *
     * `mtu` is the link's own MTU, for its interface and for its clients; null (or '') leaves it
     * to wg-quick again.
     *
     * A new `address` in another subnet needs `move_peers`: each peer then keeps its host number
     * there (10.0.0.5 → 10.1.0.5), and every client needs its new config.
     *
     * `address6` 'auto' gives a link without IPv6 a random unique local /64; one that has IPv6
     * keeps its prefix. A value the link has already is no change (no restart).
     *
     * `endpoint` is where its clients connect (host, or host:port); null (or '') detects it anew.
     * Every client config changes with it: clients need their new one.
     *
     * `destinations` are the only networks traffic out of its tunnel is forwarded (and NATed) to;
     * null (or '') takes them away: anywhere again. Applied live, like forward and NAT.
     */
    public function updateLink(string $name, array $params): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        // Nothing asked: nothing written either, the link as it is
        if ($params === []) {
            return $this->getLink($name) ?? throw NotFoundException::link($name);
        }

        // Validate provided fields
        if (isset($params['port'])) {
            $this->validator->validatePort((int) $params['port']);
        }
        if (isset($params['address'])) {
            // Without a mask it keeps the link's own, known under the lock
            str_contains($params['address'], '/')
                ? $params['address'] = $this->validator->linkAddress($params['address'])
                : $this->validator->validateIpAddress($params['address']);
        }
        if (array_key_exists('endpoint', $params)) {
            $params['endpoint'] = in_array($params['endpoint'], [null, ''], true) ? $this->detectedEndpoint() : $this->validator->endpoint((string) $params['endpoint']);
        }
        // Format only: the full check needs the link's IPv4 address, read under the lock
        if (isset($params['address6']) && ! in_array($params['address6'], ['', 'none', 'auto'], true)) {
            $this->validator->address6((string) $params['address6'], '0.0.0.0/32');
        }
        $params = $this->validateSettings($params);
        if (isset($params['ifout'])) {
            $system_interfaces = $this->os->networkInterfaces();
            if (! in_array($params['ifout'], $system_interfaces)) {
                throw new InvalidArgumentException("Output interface does not exist: {$params['ifout']}");
            }
        }

        return $this->withLock(function () use ($name, $params) {
            $content = $this->managedConf($name);
            $parsed = $this->configBuilder->parseConfContent($content);
            $meta = $parsed['metadata'];
            if (isset($params['address']) && ! str_contains($params['address'], '/')) {
                $params['address'] = $this->validator->linkAddress($params['address'].'/'.(explode('/', $meta['address'] ?? '', 2)[1] ?? '24'));
            }

            // What the link has already is no change: sent again (a client that sends the whole
            // state), it must not restart the link, and `auto` must not give it a new prefix
            if (isset($params['address']) && $params['address'] === ($meta['address'] ?? null)) {
                unset($params['address']);
            }
            if (isset($params['port']) && (int) $params['port'] === (int) ($parsed['interface']['ListenPort'] ?? 0)) {
                unset($params['port']);
            }
            if (($params['address6'] ?? null) === 'auto' && isset($meta['address6'])) {
                unset($params['address6']);
            }

            // IPv6: a new value (null removes it), else the current one, checked against the IPv4 address
            $address = $params['address'] ?? $meta['address'] ?? '';
            $current6 = $meta['address6'] ?? null;
            $address6 = array_key_exists('address6', $params)
                ? $this->resolveAddress6($params['address6'], $address)
                : ($current6 === null ? null : $this->validator->address6($current6, $address));
            $changed6 = $address6 !== $current6;

            if (isset($params['port']) || isset($params['address']) || $changed6) {
                $this->assertNoClash(
                    isset($params['port']) ? (int) $params['port'] : null,
                    isset($params['address']) ? $params['address'] : null,
                    $this->otherLinks($name),
                    $changed6 ? $address6 : null,
                );
            }
            // Peers stay where they are unless told to move along with the link
            $moved_from = isset($params['address']) && ! empty($params['move_peers']) ? ($meta['address'] ?? null) : null;
            if (isset($params['address']) || $changed6) {
                $this->assertPeersFit($name, $address, $address6, $moved_from);
            }

            $iface = $this->runtimeInterface($name);
            $running = $iface !== null;

            $current_forward = ($meta['forward'] ?? 'false') === 'true';
            $current_nat = ($meta['nat'] ?? 'false') === 'true';
            $current_ifout = $meta['ifout'] ?? $this->os->defaultOutboundInterface();

            // The MTU is a line of the [Interface] section, not metadata (read as the parser reads
            // it: `MTU=1400` counts as managed, so it must not be lost)
            $current_mtu = isset($parsed['interface']['MTU']) ? (int) $parsed['interface']['MTU'] : null;
            $mtu = array_key_exists('mtu', $params) ? (in_array($params['mtu'], [null, ''], true) ? null : (int) $params['mtu']) : $current_mtu;
            if ($mtu !== null) {
                $this->validator->validateMtu($mtu, $address6 !== null);
            }

            $forward = array_key_exists('forward', $params) ? (bool) $params['forward'] : $current_forward;
            $nat = array_key_exists('nat', $params) ? (bool) $params['nat'] : $current_nat;
            $ifout = $params['ifout'] ?? $current_ifout;
            $up = array_key_exists('up', $params) ? (bool) $params['up'] : $running;
            $current_inbound = ($meta['inbound'] ?? 'false') === 'true';
            $inbound = array_key_exists('inbound', $params) ? (bool) $params['inbound'] : $current_inbound;
            $current_destinations = $meta['destinations'] ?? null;
            $destinations = array_key_exists('destinations', $params) ? $params['destinations'] : $current_destinations;

            // What its peers may route: on only where the server allows it, off only where no peer needs it
            $routes = [];
            foreach (['allow_default_route', 'allow_own_networks'] as $field) {
                $routes[$field] = array_key_exists($field, $params) ? (bool) $params[$field] : ($meta[$field] ?? 'false') === 'true';
            }
            $this->assertPolicyAllows(
                $routes['allow_default_route'] && ($meta['allow_default_route'] ?? 'false') !== 'true',
                $routes['allow_own_networks'] && ($meta['allow_own_networks'] ?? 'false') !== 'true',
            );
            // (The tunnel addresses in the config are those of the current prefix)
            $networks = array_merge([], ...array_map(fn (array $peer) => IpAllocator::networksOf($peer['AllowedIPs'] ?? '', $current6), $parsed['peers']));
            if (($problems = $this->routeProblems($networks, $routes['allow_default_route'], $routes['allow_own_networks'])) !== []) {
                throw new ConflictException("Its peers route what that would no longer allow: {$problems[0]}");
            }

            // Metadata overrides, only for fields that were provided
            $overrides = [];
            foreach (['ifout', 'address', 'endpoint'] as $field) {
                if (isset($params[$field])) {
                    $overrides[$field] = (string) $params[$field];
                }
            }
            // The link's own client settings: null takes one out, back to the fixed default
            // (and its destinations: null takes them away, anywhere again)
            foreach (['dns', 'keepalive', 'allowed_ips', 'destinations'] as $field) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = $params[$field] === null ? null : (string) $params[$field];
                }
            }
            if (isset($params['port'])) {
                $overrides['port'] = (string) $params['port'];
            }
            $overrides['address6'] = $address6;
            $overrides['mtu'] = $mtu;
            foreach (['forward' => $forward, 'nat' => $nat, 'inbound' => $inbound, ...$routes] as $field => $value) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = $value ? 'true' : 'false';
                }
            }

            // Addresses and port are applied by wg-quick, so a running link has to restart
            $readdress = isset($params['address']) || $changed6;
            $restart = $running && $up && ($readdress || isset($params['port']) || $mtu !== $current_mtu);

            // Rewrite while the interface still exists: a running link's peers are read from it.
            // Peers' IPv6 addresses mirror their IPv4 host number, so they move with the addresses.
            $this->rewriteConf($name, $content, $iface, $overrides, $readdress && ($address6 !== null || $current6 !== null || $moved_from !== null)
                ? fn (array $peers) => $this->readdressPeers($peers, $address, $address6, $current6, $moved_from)
                : null);

            try {
                if ($up && (! $running || $restart)) {
                    // Before anything stops: a link that runs keeps running if it couldn't start
                    $this->assertRemotesResolve($name);
                }
                if ($running && (! $up || $restart)) {
                    $this->os->stopInterface($name);
                    $this->os->clearFirewall($name);
                }

                if ($up && (! $running || $restart)) {
                    // PostUp installs the rules for the new state
                    $this->os->startInterface($name);
                } elseif ($running && $up && ($forward !== $current_forward || $nat !== $current_nat || $ifout !== $current_ifout || $inbound !== $current_inbound || $destinations !== $current_destinations)) {
                    // The rules come from the config rewritten above
                    $this->os->applyFirewall($name, $iface);
                }
            } catch (\Throwable $e) {
                throw $this->revert($name, $content, $running, $e);
            }

            // Client configs are built when they are asked for: nothing to bring up to date
            return $this->getLink($name) ?? throw NotFoundException::link($name);
        });
    }

    // ─── Adoption ────────────────────────────────────────────────────

    /**
     * Take a config the app didn't write under its management, in place: one written by hand, or
     * by the API before this one (hooks that set up iptables, peers with a preshared key and a
     * /32 each). Such a config is shown but never changed (assertManaged()), because the app
     * writes configs whole and would drop what it doesn't write. Here that is asked for.
     *
     * - Kept exactly: the private key (so the link's public key), the listen port, the addresses,
     *   an MTU, and every peer with its public key, preshared key and allowed IPs (its tunnel
     *   address and the networks behind it). No client notices.
     * - Dropped: what the app replaces. Hooks (it installs the link's forward and NAT rules
     *   itself, as $params say), comments, SaveConfig (it writes the config itself).
     * - Refused, by name (`not_adoptable`): anything else. Table, DNS, FwMark, a keepalive the
     *   server sends a peer, a peer's Endpoint that is no host:port, a second address.
     *
     * $params are link settings as updateLink() takes them: ifout, forward, nat, inbound,
     * destinations, endpoint, mtu, dns, keepalive, allowed_ips, allow_default_route and
     * allow_own_networks. The hooks are not read for what they did: without `forward` and `nat`
     * the adopted link has neither.
     *
     * A peer's private key is not in a link config. A peer whose key is stored here keeps it; one
     * the older API left a client config of (in the link's client directory) gets its key from
     * there; any other is a peer with a key of its own, whose client config comes without the
     * PrivateKey line. The answer says which is which.
     *
     * A running link restarts. It stops with its own config still in place, so that its own
     * PostDown takes down what its PostUp set up, starts with the new one, and if it doesn't come
     * up, the previous config goes back and the link runs again as it did (the root helper keeps
     * that config meanwhile: it never takes one with hooks of its own from the app). A stopped
     * link stays stopped.
     *
     * With $dry_run everything is checked and nothing is changed: the answer is what the real
     * call would give, with the link as it would be.
     *
     * @return array{link: InterfaceInfo, adoption: array{dry_run: bool, restarts: bool, kept: array, dropped: array<string, int>, applied: array, keys: array{stored: list<string>, imported: list<string>, own: list<string>}, warnings: list<string>}}
     */
    public function adoptLink(string $name, array $params = [], bool $dry_run = false): array
    {
        $this->validator->validateInterfaceName($name);
        if (isset($params['endpoint']) && $params['endpoint'] !== '') {
            $params['endpoint'] = $this->validator->endpoint((string) $params['endpoint']);
        }
        $params = $this->validateSettings($params);
        if (isset($params['ifout']) && ! in_array($params['ifout'], $this->os->networkInterfaces(), true)) {
            throw new InvalidArgumentException("Output interface does not exist: {$params['ifout']}");
        }

        return $this->withLock(function () use ($name, $params, $dry_run) {
            $content = $this->os->readConfig($name) ?? throw $this->withoutConfig($name);
            if ($this->unmanagedSettings($content) === []) {
                throw new ConflictException("Link {$name} is managed already: there is nothing to adopt. Change it like any other link (PATCH /link/{$name}, wgla link:update {$name}).", ErrorCode::ALREADY_MANAGED);
            }

            $iface = $this->runtimeInterface($name);
            $running = $iface !== null;
            $plan = $this->adoptionPlan($name, $content, $iface, $params);
            // The helper writes it, so the helper says whether it would. And a link that restarts
            // must be able to start: before anything stops.
            $this->os->checkConfig($name, $plan['content']);
            if ($running) {
                $this->assertRemotesResolve($name, $plan['peers']);
            }
            if ($dry_run) {
                return [
                    'link' => $this->linkFromConf($name, $plan['content'])->with(up: $running, interface: $iface),
                    'adoption' => ['dry_run' => true, 'restarts' => $running, ...$plan['report']],
                ];
            }

            if ($running) {
                $plan = $this->stopForAdoption($name, $plan);
            }
            try {
                $this->os->adoptConfig($name, $plan['content']);
            } catch (\Throwable $e) {
                // Its own config is still in place: as it was
                throw $this->notAdopted($name, $running, $e);
            }

            $imported = [];
            try {
                // Before it starts: a peer's client config is complete from the first moment on
                $imported = $this->os->importLegacyClientKeys($name);
                if ($running) {
                    $this->os->startInterface($name);
                }
            } catch (\Throwable $e) {
                throw $this->unadopt($name, $running, $imported, $e);
            }
            $this->os->confirmAdoptedConfig($name);

            $keys = $plan['report']['keys'];
            $keys['imported'] = array_values(array_intersect(array_column($plan['peers'], 'public_key'), $imported));
            $keys['own'] = array_values(array_diff(array_column($plan['peers'], 'public_key'), $keys['stored'], $keys['imported']));

            return [
                'link' => $this->linkOrFail($name),
                'adoption' => ['dry_run' => false, 'restarts' => $running, ...$plan['report'], 'keys' => $keys],
            ];
        });
    }

    /**
     * Stop a running link that is about to be adopted, with its own config still in place:
     * wg-quick then runs that config's PostDown (what its PostUp set up goes with it), and saves
     * the interface into a config with SaveConfig. Returns the plan to go on with, which is the
     * one that was made: what the dry run answered is what is done.
     *
     * wg-quick takes the interface down before it runs a config's PostDown. So a stop that fails
     * may well have stopped the link: one whose own hook failed (a rule it was to delete was gone
     * already) is down, and is adopted, with a warning. Only one that still runs was not stopped.
     */
    protected function stopForAdoption(string $name, array $plan): array
    {
        $unclean = null;
        try {
            $this->os->stopInterface($name);
        } catch (\Throwable $e) {
            $unclean = $e;
        }

        try {
            $stopped = $this->runtimeInterface($name) === null;
            if ($stopped && $plan['saves_itself']) {
                // wg-quick has just written the interface into the config. The plan has the peers
                // the interface had when it was looked at (and what only the old file's comments
                // knew, which wg-quick doesn't write): if something else changed them in between,
                // one would be lost or come back.
                $saved = array_column(array_filter(ForeignConfig::parse($this->os->readConfig($name) ?? '')->peers, fn (array $peer) => $peer['enabled']), 'public_key');
                $planned = array_column(array_filter($plan['peers'], fn (array $peer) => $peer['enabled']), 'public_key');
                if (array_diff($saved, $planned) !== [] || array_diff($planned, $saved) !== []) {
                    throw new ConflictException('its peers changed while it was being adopted (something else manages its interface): ask again');
                }
            }
        } catch (\Throwable $e) {
            throw $this->notAdopted($name, true, $e);
        }

        // It runs on with its own config: nothing was changed, and nothing is to undo
        if (! $stopped) {
            throw $unclean !== null
                ? new SystemException("Link {$name} could not be stopped, so it was not adopted, and runs on as it did: {$unclean->getMessage()}", 0, $unclean)
                : new ConflictException("Link {$name} still runs after it was stopped the way this app stops links: it was started another way (not as wg-quick@{$name}, or with a config elsewhere). Stop it where it was started, then adopt it.");
        }
        if ($unclean !== null) {
            $plan['report']['warnings'][] = "The link stopped, but not cleanly: its own PostDown may have failed, and what it was to take down may still be there. ({$unclean->getMessage()})";
        }

        return $plan;
    }

    /**
     * An adoption that ended before the link's own config was replaced: a link that was running
     * starts again with it, as it was. Returns the exception to throw.
     */
    protected function notAdopted(string $name, bool $was_running, \Throwable $e): SystemException
    {
        try {
            if ($was_running && $this->runtimeInterface($name) === null) {
                $this->os->startInterface($name);
            }
        } catch (\Throwable) {
            return $this->failedChange($name, $e, undone: false);
        }

        return $this->failedChange($name, $e, undone: true);
    }

    /**
     * Undo an adoption whose link didn't start: the config it had goes back (the helper kept it),
     * the keys stored for it go again, and a link that was running starts with its own config
     * and hooks, as it was. Returns the exception to throw.
     *
     * @param  list<string>  $imported  public keys whose private key the adoption stored
     */
    protected function unadopt(string $name, bool $was_running, array $imported, \Throwable $e): SystemException
    {
        try {
            if ($was_running) {
                // Half started, or not at all: down, and none of the app's rules left
                $this->os->stopInterface($name);
                $this->os->clearFirewall($name);
            }
            $this->os->undoAdoptedConfig($name);
            foreach ($imported as $pubkey) {
                $this->os->deleteClientConfig($name, KeyManager::pubkeyToSafe($pubkey));
            }
            if ($was_running) {
                $this->os->startInterface($name);
            }
        } catch (\Throwable) {
            return $this->failedChange($name, $e, undone: false);
        }

        return $this->failedChange($name, $e, undone: true);
    }

    /**
     * What adopting a config would write and say (adoptLink()), or why it can't be adopted.
     *
     * @param  string|null  $iface  the link's interface while it runs. A config with SaveConfig is
     *                              written from it by wg-quick when the link stops, which it does
     *                              before it starts as the app's: then the interface, not the
     *                              file, has the peers (and the key and port) that are adopted.
     * @return array{content: string, peers: list<array>, saves_itself: bool, report: array}
     */
    protected function adoptionPlan(string $name, string $content, ?string $iface, array $params): array
    {
        $config = ForeignConfig::parse($content);
        $private_key = $config->privateKey;
        $port = $config->listenPort;
        $found = $config->peers;
        $live = $iface === null ? null : $this->os->interfaceDump($iface);
        if ($config->savesItself && $live !== null) {
            [$private_key, $port, $found, $fwmark] = $this->savedByWgQuick($live, $config->peers);
            if ($fwmark) {
                $config->block('FwMark'); // wg-quick is about to write it into the config
            }
        }

        // The link itself: what it has to have, and has to have right
        foreach (['PrivateKey' => $private_key, 'ListenPort' => $port, 'Address' => $config->addresses === [] ? null : ''] as $key => $value) {
            if ($value === null) {
                $config->block("no {$key}");
            }
        }
        if ($private_key !== null && ! KeyManager::isKey($private_key)) {
            $config->block('PrivateKey');
        }
        if ($port !== null && (! ctype_digit($port) || (int) $port < 1 || (int) $port > 65535)) {
            $config->block('ListenPort');
        }
        [$address, $address6] = $this->adoptedAddresses($config->addresses);
        if ($config->addresses !== [] && $address === null) {
            $config->block('Address');
        }

        // Its own MTU stays, unless another is asked for (null: wg-quick's)
        $mtu = $config->mtu;
        if (array_key_exists('mtu', $params)) {
            $mtu = in_array($params['mtu'], [null, ''], true) ? null : (string) (int) $params['mtu'];
            if ($mtu !== null) {
                $this->validator->validateMtu((int) $mtu, $address6 !== null);
            }
        } elseif ($mtu !== null && (! ctype_digit($mtu) || (int) $mtu < ($address6 === null ? 576 : 1280) || (int) $mtu > 65535)) {
            $config->block('MTU');
        }

        // Its peers, each kept as it is
        $peers = array_map(fn (array $peer) => $this->adoptedPeer($peer, $config, $address, $address6), $found);
        $pubkeys = array_column($peers, 'public_key');
        if (count($pubkeys) !== count(array_unique($pubkeys))) {
            $config->block('PublicKey'); // the same peer twice
        }

        if ($config->blocking !== []) {
            $shown = implode(', ', array_slice($config->blocking, 0, 8)).(count($config->blocking) > 8 ? ', …' : '');

            throw new ConflictException("Link {$name} can't be adopted as it is: its config has what the app has no place for, or can't read ({$shown}). Take that out of the config (or put it right) by hand first, or go on managing the link by hand.", ErrorCode::NOT_ADOPTABLE);
        }

        // Its settings: as asked, else what the config had of the app's own (it was the app's
        // once), else as a new link's
        $meta = $config->metadata;
        $flag = fn (string $key) => array_key_exists($key, $params) ? (bool) $params[$key] : ($meta[$key] ?? 'false') === 'true';
        $own = fn (string $key) => array_key_exists($key, $params) ? $params[$key] : $this->adoptedSetting($key, $meta[$key] ?? null);
        $system_interfaces = $this->os->networkInterfaces();
        $ifout = $params['ifout']
            ?? (in_array($meta['ifout'] ?? null, $system_interfaces, true) ? $meta['ifout'] : $this->os->defaultOutboundInterface());
        $endpoint = isset($params['endpoint']) && $params['endpoint'] !== ''
            ? $params['endpoint']
            : (array_key_exists('endpoint', $params) ? null : $this->adoptedSetting('endpoint', $meta['endpoint'] ?? null)) ?? $this->detectedEndpoint();
        $settings = [
            'ifout' => $ifout,
            'forward' => $flag('forward'),
            'nat' => $flag('nat'),
            'inbound' => $flag('inbound'),
            'destinations' => $own('destinations'),
            'endpoint' => $endpoint,
            'mtu' => $mtu === null ? null : (int) $mtu,
            'dns' => $own('dns'),
            'keepalive' => ($keepalive = $own('keepalive')) === null ? null : (int) $keepalive,
            'allowed_ips' => $own('allowed_ips'),
            'allow_default_route' => $flag('allow_default_route'),
            'allow_own_networks' => $flag('allow_own_networks'),
        ];

        // What a new link is checked for: the server's policy on what peers may route, and no
        // port, subnet or routed network that another link has
        $networks = array_merge([], ...array_map(fn (array $peer) => IpAllocator::networksOf($peer['allowed_ips'], $address6), $peers));
        $this->assertPolicyAllows($settings['allow_default_route'], $settings['allow_own_networks']);
        if (($problems = $this->routeProblems($networks, $settings['allow_default_route'], $settings['allow_own_networks'])) !== []) {
            throw new ConflictException($problems[0]);
        }
        $this->assertNoClash((int) $port, $address, $this->otherLinks($name), $address6, $networks);

        // Whose private key is here: stored already, in a client config the older API left, or nowhere
        $keys = $this->os->clientKeys($name);
        $stored = array_values(array_intersect($pubkeys, $keys['stored']));
        $imported = array_values(array_diff(array_intersect($pubkeys, $keys['legacy']), $stored));

        $warnings = [];
        if (array_intersect(array_keys($config->dropped), ['PreUp', 'PostUp', 'PreDown', 'PostDown']) !== [] && ! $settings['forward'] && ! $settings['nat']) {
            $warnings[] = 'Its hooks are dropped, and nothing is put in their place: the link gets neither forward nor NAT rules. If its hooks set those up, adopt it with forward and nat (and destinations, to keep its NAT to where it went).';
        }
        if ($live !== null && ! $config->savesItself) {
            // The config is what is adopted, and what the link restarts with: where the interface
            // was changed without it (`wg set`), the restart changes it back, as any would
            $on_interface = array_column($this->parseDumpPeers(explode("\n", $live)), 'public_key');
            $enabled = array_column(array_filter($peers, fn (array $peer) => $peer['enabled']), 'public_key');
            $some = fn (array $keys) => implode(', ', array_slice($keys, 0, 5)).(count($keys) > 5 ? ', …' : '');
            if (($strays = array_values(array_diff($on_interface, $pubkeys))) !== []) {
                $warnings[] = count($strays).' of the peers on the running interface are not in the config: they are not adopted, and the restart drops them, as any restart of the link would ('.$some($strays).').';
            }
            if (($absent = array_values(array_diff($enabled, $on_interface))) !== []) {
                $warnings[] = count($absent).' of the peers in the config are not on the running interface (taken off it, or never loaded): they are adopted, and the restart brings them back, as any restart of the link would ('.$some($absent).').';
            }
        }

        return [
            'content' => $this->configBuilder->buildConfFile(
                $address, $private_key, (int) $port, $settings['ifout'], $peers, $settings['dns'], $settings['keepalive'], $settings['allowed_ips'],
                $settings['forward'], $settings['nat'], $address6, $settings['mtu'], $settings['inbound'], $settings['allow_default_route'],
                $settings['allow_own_networks'], $settings['endpoint'], $settings['destinations'],
            ),
            'peers' => $peers,
            'saves_itself' => $config->savesItself,
            'report' => [
                'kept' => ['public_key' => $this->keys->pubkey($private_key), 'listen_port' => (int) $port, 'address' => $address, 'address6' => $address6, 'peers' => count($peers)],
                'dropped' => $config->dropped,
                'applied' => $settings,
                'keys' => ['stored' => $stored, 'imported' => $imported, 'own' => array_values(array_diff($pubkeys, $stored, $imported))],
                'warnings' => $warnings,
            ],
        ];
    }

    /**
     * A link's addresses from its Address lines, as the app holds them: one IPv4 address with
     * its mask and at most one IPv6 one. [null, null] for anything else.
     *
     * @param  list<string>  $addresses
     * @return array{0: ?string, 1: ?string}
     */
    protected function adoptedAddresses(array $addresses): array
    {
        $v6 = array_values(array_filter($addresses, fn (string $address) => str_contains($address, ':')));
        $v4 = array_values(array_diff($addresses, $v6));
        if (count($v4) !== 1 || count($v6) > 1) {
            return [null, null];
        }

        try {
            // As it is: an existing link's address isn't held to what a new one must be
            $address = $this->validator->validateCidr($v4[0]);

            return [$address, $v6 === [] ? null : $this->validator->address6($v6[0], $address)];
        } catch (InvalidArgumentException) {
            return [null, null];
        }
    }

    /**
     * One of the app's own settings as a config to adopt has it in a comment, if it is one the
     * app would write; else null (it is a comment like any other then, and dropped).
     */
    protected function adoptedSetting(string $key, ?string $value): ?string
    {
        if ($value === null) {
            return null;
        }

        try {
            return match ($key) {
                'endpoint' => $this->validator->endpoint($value),
                'keepalive' => ctype_digit($value) && (int) $value <= 65535 ? $value : null,
                default => $this->validateSettings([$key => $value])[$key],
            };
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /**
     * A peer of a config to adopt, as the app writes peers. What it has that the app has no place
     * for is added to what blocks the adoption ($config->block()).
     *
     * Its allowed IPs stay what they are, each written as wg itself reads it (a bare address is
     * a host, a network comes without its host bits), with its own tunnel address first: that is
     * where the app looks for it.
     */
    protected function adoptedPeer(array $peer, ForeignConfig $config, ?string $address, ?string $address6): array
    {
        if ($peer['public_key'] === null || ! KeyManager::isKey($peer['public_key'])) {
            $config->block('PublicKey');
        }
        if ($peer['preshared_key'] !== null && ! KeyManager::isKey($peer['preshared_key'])) {
            $config->block('PresharedKey');
        }

        $allowed = [];
        try {
            foreach ($peer['allowed_ips'] as $entry) {
                $this->validator->validateAllowedIps($entry);
                $allowed[] = IpAllocator::networkCidr($entry);
            }
        } catch (InvalidArgumentException) {
            $config->block('AllowedIPs');
        }
        $allowed = array_values(array_unique($allowed));
        if ($allowed === []) {
            $config->block('AllowedIPs'); // none: nothing the app could write
        }
        // To the app a peer is its address in the link's subnet: that is where its client config
        // and every later change to it start from. One without can't be one of the app's.
        $tunnel = $address === null ? null : array_find($allowed, fn (string $entry) => $this->hasTunnelAddress($entry, $address));
        if ($address !== null && $allowed !== [] && $tunnel === null) {
            $config->block("a peer without an address of its own (a /32) in the link's subnet");
        }
        if ($tunnel !== null) {
            $allowed = [$tunnel, ...array_values(array_diff($allowed, [$tunnel]))];
        }
        if ($tunnel !== null && $address6 !== null) {
            // And on a dual-stack link, the IPv6 address its IPv4 one gives it: the one its client
            // config has. None, or another one in the link's prefix, and that config would be wrong.
            $mirror = $this->mirrored(substr($tunnel, 0, -3), $address, $address6);
            $in_prefix = array_values(array_filter($allowed, fn (string $entry) => str_ends_with($entry, '/128') && IpAllocator::overlaps($entry, $address6)));
            if ($in_prefix !== [$mirror]) {
                $config->block("a peer without the IPv6 address its IPv4 one gives it in the link's prefix, or with another");
            } else {
                $allowed = [$tunnel, $mirror, ...array_values(array_diff($allowed, [$tunnel, $mirror]))];
            }
        }

        // Where the server connects to it: the app's `remote`, which comes with the keepalive the
        // app sends such a peer. In a config wg-quick saves, it is only where the peer was last seen.
        $remote = null;
        $keepalive = $peer['persistent_keepalive'];
        $sends = $keepalive !== null && ! in_array(strtolower($keepalive), ['0', 'off'], true);
        if ($peer['endpoint'] !== null && ! $config->savesItself) {
            try {
                $remote = $this->validator->remote($peer['endpoint']);
            } catch (InvalidArgumentException) {
                $config->block('Endpoint');
            }
            if ($sends && $keepalive !== (string) ConfigBuilder::REMOTE_KEEPALIVE) {
                $config->block('PersistentKeepalive');
            }
        } else {
            if ($sends) {
                $config->block('PersistentKeepalive');
            }
            // (Of a running link whose config wg-quick saves, these are the lines it is about to write)
            foreach (['Endpoint' => $peer['endpoint'], 'PersistentKeepalive' => $keepalive] as $key => $value) {
                if ($value !== null && ! ($key === 'PersistentKeepalive' && $sends)) {
                    $config->drop($key);
                }
            }
        }

        // What the app keeps with a peer in comments (it was the app's once): as it writes it, or not at all
        $name = null;
        try {
            $name = $peer['name'] === null ? null : $this->validator->peerName($peer['name']);
        } catch (InvalidArgumentException) {
        }

        return array_filter([
            'public_key' => (string) $peer['public_key'],
            'preshared_key' => $peer['preshared_key'],
            'allowed_ips' => implode(', ', $allowed),
            'name' => $name,
            'remote' => $remote,
            'enabled' => $peer['enabled'],
            'dns' => $this->adoptedSetting('dns', $peer['dns']),
            'keepalive' => $this->adoptedSetting('keepalive', $peer['keepalive']),
            'client_allowed_ips' => $this->adoptedSetting('allowed_ips', $peer['client_allowed_ips']),
        ], fn (mixed $value, string $key) => $value !== null || $key !== 'preshared_key', ARRAY_FILTER_USE_BOTH);
    }

    /** The /128 the app gives a peer in its link's prefix (IpAllocator::mirror()), or null where there is no room for it. */
    protected function mirrored(string $ip, string $address, string $address6): ?string
    {
        try {
            return IpAllocator::mirror($ip, $address, $address6).'/128';
        } catch (InvalidArgumentException) {
            return null;
        }
    }

    /** Whether allowed IPs start with (or an entry is) a peer's own address in a link: a /32 inside its subnet. */
    protected function hasTunnelAddress(string $allowed_ips, string $address): bool
    {
        $first = trim(explode(',', $allowed_ips, 2)[0]);

        return ! str_contains($first, ':') && str_ends_with($first, '/32') && $this->validator->ipInRange(substr($first, 0, -3), $address);
    }

    /**
     * What wg-quick writes into a config with SaveConfig when its link stops (`wg showconf`): the
     * interface's key, port and peers, each with where it was last seen. A peer the app disabled
     * is not on the interface, and stays as the config has it.
     *
     * @param  string  $dump  `wg show <iface> dump`
     * @param  list<array>  $sections  the config's peers (ForeignConfig), for what only they know
     * @return array{0: ?string, 1: ?string, 2: list<array>, 3: bool} private key, port, peers, whether it has a firewall mark (which wg-quick saves too)
     */
    protected function savedByWgQuick(string $dump, array $sections): array
    {
        $lines = explode("\n", $dump);
        $interface = explode("\t", $lines[0]);
        $known = array_column(array_filter($sections, fn (array $peer) => $peer['public_key'] !== null), null, 'public_key');

        $peers = [];
        foreach (array_slice($lines, 1) as $line) {
            $parts = explode("\t", $line);
            if (count($parts) < 4) {
                continue;
            }
            $peers[] = [
                ...($known[$parts[0]] ?? ForeignConfig::peer()),
                'public_key' => $parts[0],
                'preshared_key' => $parts[1] === '(none)' ? null : $parts[1],
                'allowed_ips' => $parts[3] === '(none)' ? [] : explode(',', $parts[3]),
                'endpoint' => $parts[2] === '(none)' ? null : $parts[2],
                'persistent_keepalive' => in_array($parts[7] ?? 'off', ['off', '0'], true) ? null : $parts[7],
                'enabled' => true,
            ];
        }

        return [
            in_array($interface[0] ?? '', ['', '(none)'], true) ? null : $interface[0],
            $interface[2] ?? null,
            [...$peers, ...array_values(array_filter($sections, fn (array $peer) => ! $peer['enabled']))],
            ! in_array($interface[3] ?? 'off', ['off', '0', ''], true),
        ];
    }

    // ─── Peer operations ─────────────────────────────────────────────
    //
    // On a running link the .conf is regenerated from the live interface with the change, which
    // is then applied with `wg` (applyLive(), undone if the host refuses it). On a stopped link
    // only the .conf is edited; wg-quick loads it on the next start.

    /**
     * Add a peer: the next free address unless $ip is given, an optional label, and optional
     * networks behind it (site-to-site), which wg-quick routes to it.
     *
     * Its keys are made here, unless it brings its own public key (another server of this kind,
     * a device that made its own): then no private key is stored, and its client config comes
     * without the PrivateKey line. A preshared key may be given likewise (both sides need it).
     * `dns`, `keepalive` and `allowed_ips` are its own client settings, as with updatePeer();
     * `enabled` false adds it disabled (saved, not on the interface).
     */
    public function addPeer(string $link_name, ?string $ip = null, ?string $name = null, ?string $networks = null, ?string $remote = null, ?string $public_key = null, ?string $preshared_key = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $enabled = true): PeerInfo
    {
        $this->validator->validateInterfaceName($link_name);
        $name = $name === null || $name === '' ? null : $this->validator->peerName($name);
        $networks = $networks === null || $networks === '' ? [] : $this->validator->networks($networks);
        $remote = $remote === null || $remote === '' ? null : $this->resolvableRemote($remote);
        $public_key = $public_key === null || $public_key === '' ? null : $this->validator->key($public_key, 'public key');
        $preshared_key = $preshared_key === null || $preshared_key === '' ? null : $this->validator->key($preshared_key, 'preshared key');
        $own = $this->validateSettings(['dns' => $dns, 'keepalive' => $keepalive, 'allowed_ips' => $allowed_ips]);

        return $this->withLock(function () use ($link_name, $ip, $name, $networks, $remote, $public_key, $preshared_key, $own, $enabled) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw NotFoundException::link($link_name);
            }
            $conf = $this->managedConf($link_name);
            if ($public_key !== null && $this->findPeer($link, $public_key) !== null) {
                throw new ConflictException("Link {$link_name} has a peer with that public key already.");
            }

            // Auto-assign IP if not provided
            $bare_ip = $ip === null || $ip === ''
                ? $this->ipAllocator->findAvailableIp($link->address, $link->peers, $link->address6)
                : $this->validator->peerAddress($ip);

            // Validate peer IP
            $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers);
            $this->validator->validateNewPeerIp($bare_ip, $link->address, $existing_ips, $link->address6);
            $this->assertNetworksFree($link, $networks);

            // Generate keys (base64), unless it brought its own
            $privkey = $public_key === null ? $this->keys->genkey() : null;
            $pubkey = $public_key ?? $this->keys->pubkey($privkey);

            $peer = [
                'public_key' => $pubkey,
                'preshared_key' => $preshared_key ?? $this->keys->genpsk(),
                'allowed_ips' => implode(', ', [IpAllocator::peerAllowedIps($bare_ip, $link->address, $link->address6), ...$networks]),
                'name' => $name,
                'remote' => $remote,
                'enabled' => $enabled,
                'dns' => $own['dns'],
                'keepalive' => $own['keepalive'] === null ? null : (string) $own['keepalive'],
                'client_allowed_ips' => $own['allowed_ips'],
            ];

            // Only its private key is stored (by base64url-safe public key): the client config is
            // built from it whenever it is asked for. Stored first, so the peer is never there
            // without it: a peer whose key is lost can't be used, and nobody would know its key
            if ($privkey !== null) {
                $this->os->writeClientConfig($link_name, KeyManager::pubkeyToSafe($pubkey), ConfigBuilder::clientKeyFile($privkey));
            }

            try {
                $this->rewriteConf($link_name, $conf, $iface, peers: fn (array $peers) => $this->putPeer($peers, $peer));
                if ($iface !== null && $enabled && $networks === []) {
                    // On stdin: the preshared key is never on a command line (the helper keeps it
                    // in a private temp file only while it checks it)
                    $this->applyLive($link_name, $conf, [[fn () => $this->os->addPeer($iface, $this->peerSection($peer)), null]]);
                } elseif ($iface !== null && $enabled) {
                    // wg-quick routes the networks when the link starts
                    $this->restartOrRevert($link_name, $conf);
                }
            } catch (\Throwable $e) {
                if ($privkey !== null) {
                    $this->forgetKey($link_name, $pubkey);
                }

                throw $e;
            }

            return $this->peerInfo($peer, $link->address6, $link, $privkey, reveal: true);
        });
    }

    public function removePeer(string $link_name, string $pubkey): void
    {
        [$link_name, $pubkey] = $this->peerAddress($link_name, $pubkey);

        $this->withLock(function () use ($link_name, $pubkey) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw NotFoundException::link($link_name);
            }

            $target = $this->findPeer($link, $pubkey);
            if ($target === null) {
                throw NotFoundException::peer($pubkey);
            }
            $conf = $this->managedConf($link_name);

            // wg-quick routed the networks behind it when the link started, and only a restart
            // takes those routes away again (as when updatePeer() changes them)
            $reroute = $iface !== null && $target->enabled && $target->networks !== null;
            // A disabled peer isn't on the interface
            if ($iface !== null && $target->enabled && ! $reroute) {
                $this->os->removePeer($iface, $pubkey);
            }
            $this->rewriteConf($link_name, $conf, $iface, peers: fn (array $peers) => array_values(
                array_filter($peers, fn (array $p) => $p['public_key'] !== $pubkey),
            ));
            if ($reroute) {
                $this->restartOrRevert($link_name, $conf);
            }

            try {
                $this->os->deleteClientConfig($link_name, KeyManager::pubkeyToSafe($pubkey));
            } catch (CommandFailedException $e) {
                throw new SystemException("Peer {$pubkey} was removed from link {$link_name}, but its stored private key could not be deleted: {$e->getMessage()}", 0, $e);
            }
        });
    }

    /**
     * A peer of a link, or null when there is none. Takes the public key in either form (base64
     * or URL-safe); a malformed key or link name is simply not there.
     */
    public function getPeer(string $link_name, string $pubkey): ?PeerInfo
    {
        $pubkey = KeyManager::normalize($pubkey);
        if (! $this->isLinkName($link_name) || ! KeyManager::isKey($pubkey)) {
            return null;
        }
        $link = $this->loadLink($link_name, $this->runtimeInterface($link_name));

        return $link === null ? null : $this->findPeer($link, $pubkey);
    }

    /**
     * A peer's client config, built now from the link's settings, the peer's own and its stored
     * private key: it is always current. A peer whose key isn't stored here (it brought its own,
     * or its config was written by hand) gets it without the PrivateKey line: the device adds its
     * own. Null when the peer doesn't exist. $with_key: refuse that (a QR code is the whole config).
     */
    public function getPeerConfig(string $link_name, string $pubkey, bool $with_key = false): ?string
    {
        if (! $this->isLinkName($link_name) || ! KeyManager::isKey(KeyManager::normalize($pubkey))) {
            return null;
        }

        try {
            return $this->peerConfigOrFail($link_name, $pubkey, $with_key);
        } catch (NotFoundException|ConflictException) {
            return null;
        }
    }

    /**
     * getPeerConfig(), saying why there is none: the link or the peer isn't there (a
     * NotFoundException with its code), or it is a peer nobody here has a config for (a
     * ConflictException): one of an interface something else started, which isn't this app's to
     * hand out configs for, or one without a tunnel address.
     */
    public function peerConfigOrFail(string $link_name, string $pubkey, bool $with_key = false): string
    {
        $link = $this->loadLink($link_name, $this->runtimeInterface($link_name)) ?? throw NotFoundException::link($link_name);
        $peer = $this->findPeer($link, KeyManager::normalize($pubkey)) ?? throw NotFoundException::peer($pubkey);
        $pubkey = $peer->public_key;
        if (! $this->os->configExists($link_name)) {
            throw $this->withoutConfig($link_name);
        }

        $privkey = $this->storedKey($link_name, $pubkey);
        if ($with_key && $privkey === null) {
            throw new InvalidArgumentException("The private key of peer {$pubkey} isn't stored here (it has a key of its own): its config has no PrivateKey line, so there is no QR code of it.");
        }

        return $this->clientConfig($link, $peer, $privkey)
            ?? throw new ConflictException("Peer {$pubkey} has no IPv4 tunnel address in its allowed IPs: there is no client config of it.");
    }

    /**
     * The link name and public key a change to a peer is addressed with, checked: one that is
     * malformed is the caller's mistake (invalid input), not a link or peer that isn't there.
     * The key comes back as wg writes it, from either form.
     *
     * @return array{0: string, 1: string}
     */
    protected function peerAddress(string $link_name, string $pubkey): array
    {
        $this->validator->validateInterfaceName($link_name);

        return [$link_name, $this->validator->key($pubkey, 'public key')];
    }

    /** Where this server is reached as an endpoint, as it is written: detected (ConfigBuilder::detectedHost()). */
    protected function detectedEndpoint(): string
    {
        $host = $this->configBuilder->detectedHost(fresh: true);
        try {
            return $this->validator->endpoint($host);
        } catch (InvalidArgumentException) {
            throw new InvalidArgumentException("This server's name ({$host}) is no address clients can connect to: give the link one (endpoint).");
        }
    }

    /** A peer's private key as stored here, or null (one that brought its own key has none here). */
    protected function storedKey(string $link_name, string $pubkey): ?string
    {
        return ConfigBuilder::clientPrivateKey($this->os->readClientConfig($link_name, KeyManager::pubkeyToSafe($pubkey)));
    }

    /**
     * $privkey: the peer's private key when the caller has it, else the stored one (if any).
     */
    protected function clientConfig(InterfaceInfo $link, PeerInfo $peer, ?string $privkey = null): ?string
    {
        return $this->configBuilder->buildClientConfig($link, $peer, $privkey ?? $this->storedKey($link->name, $peer->public_key));
    }

    /**
     * Change a peer.
     *
     * - `ip` moves its tunnel address: the server-side AllowedIPs, and so its client config's Address.
     * - `dns`, `allowed_ips` and `keepalive` only change what its client config hands out: the
     *   peer's own values instead of the link's client defaults, just like `allowed_ips` on a
     *   link. They are stored with the peer in the link config. null (or '') takes one out: the
     *   peer follows its link again.
     * - `name` labels it (null or '' removes the label).
     * - `enabled` false takes it off the interface but keeps its keys, address and client config.
     * - `remote` (host:port) makes the server connect to it, and keep the connection open, instead
     *   of waiting for it (null or '' removes it).
     * - `networks` are routed to it (site-to-site; null or '' removes them). wg-quick sets up the
     *   routes, so a change to the routed networks restarts a running link. If the link doesn't
     *   start with them, the change is undone.
     */
    public function updatePeer(string $link_name, string $pubkey, array $params): PeerInfo
    {
        [$link_name, $pubkey] = $this->peerAddress($link_name, $pubkey);
        // Nothing asked: nothing written either, the peer as it is (with its client config, as after a change)
        if ($params === []) {
            $link = $this->linkOrFail($link_name);
            $peer = $this->findPeer($link, $pubkey) ?? throw NotFoundException::peer($pubkey);

            return $peer->with(client_config: $this->clientConfig($link, $peer));
        }
        $params = $this->validateSettings($params);
        if (array_key_exists('name', $params)) {
            $params['name'] = $params['name'] === null || $params['name'] === '' ? null : $this->validator->peerName((string) $params['name']);
        }
        if (array_key_exists('networks', $params)) {
            $params['networks'] = $params['networks'] === null || $params['networks'] === '' ? [] : $this->validator->networks((string) $params['networks']);
        }
        if (array_key_exists('remote', $params)) {
            $params['remote'] = $params['remote'] === null || $params['remote'] === '' ? null : $this->resolvableRemote((string) $params['remote']);
        }

        return $this->withLock(function () use ($link_name, $pubkey, $params) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw NotFoundException::link($link_name);
            }

            $target = $this->findPeer($link, $pubkey);
            if ($target === null) {
                throw NotFoundException::peer($pubkey);
            }

            $conf = $this->managedConf($link_name);

            $old_networks = IpAllocator::networksOf($target->allowed_ips, $link->address6);
            $networks = $params['networks'] ?? $old_networks;
            $allowed_ips = $target->allowed_ips;

            if (isset($params['ip']) || array_key_exists('networks', $params)) {
                $bare_ip = IpAllocator::tunnelIp($target->allowed_ips);
                if (isset($params['ip'])) {
                    $bare_ip = $this->validator->peerAddress($params['ip']);
                    $others = array_filter($link->peers, fn (PeerInfo $p) => $p->public_key !== $pubkey);
                    $this->validator->validateNewPeerIp($bare_ip, $link->address, array_map(fn (PeerInfo $p) => $p->allowed_ips, $others), $link->address6);
                }
                if ($bare_ip === null) {
                    throw new InvalidArgumentException("Peer {$pubkey} has no IPv4 tunnel address; give it one with `ip`.");
                }
                $this->assertNetworksFree($link, $networks, $pubkey);
                $allowed_ips = implode(', ', [IpAllocator::peerAllowedIps($bare_ip, $link->address, $link->address6), ...$networks]);
            }

            $enabled = array_key_exists('enabled', $params) ? (bool) $params['enabled'] : $target->enabled;
            $peer = [
                'public_key' => $pubkey,
                'preshared_key' => $target->preshared_key,
                'allowed_ips' => $allowed_ips,
                'name' => array_key_exists('name', $params) ? $params['name'] : $target->name,
                'enabled' => $enabled,
                'remote' => array_key_exists('remote', $params) ? $params['remote'] : $target->remote,
            ];
            // Its own client settings, where given (param => peer field): null takes one out
            foreach (['dns' => 'dns', 'keepalive' => 'keepalive', 'allowed_ips' => 'client_allowed_ips'] as $param => $field) {
                if (array_key_exists($param, $params)) {
                    $peer[$field] = $params[$param] === null ? null : (string) $params[$param];
                }
            }

            // Live changes, unless the routed networks change: then the link restarts with the config.
            // Each with what puts the peer back as it was, should a later one fail.
            $reroute = $iface !== null && ($target->enabled ? $old_networks : []) != ($enabled ? $networks : []);
            $steps = [];
            if ($iface !== null && ! $reroute) {
                $before = ['public_key' => $pubkey, 'preshared_key' => $target->preshared_key, 'allowed_ips' => $target->allowed_ips, 'remote' => $target->remote];
                if (! $target->enabled && $enabled) {
                    $steps[] = [fn () => $this->os->addPeer($iface, $this->peerSection($peer)), null];
                } elseif ($target->enabled && ! $enabled) {
                    $steps[] = [fn () => $this->os->removePeer($iface, $pubkey), null];
                } elseif ($target->enabled) {
                    if ($allowed_ips !== $target->allowed_ips) {
                        $steps[] = [
                            fn () => $this->os->setPeerAllowedIps($iface, $pubkey, $allowed_ips),
                            fn () => $this->os->setPeerAllowedIps($iface, $pubkey, (string) $target->allowed_ips),
                        ];
                    }
                    if ($peer['remote'] !== $target->remote) {
                        if ($peer['remote'] === null) {
                            // `wg` can set where to connect to, but not take that away: off the
                            // interface, and on again without it
                            $steps[] = [fn () => $this->os->removePeer($iface, $pubkey), fn () => $this->os->addPeer($iface, $this->peerSection($before))];
                        }
                        // For a peer that is on the interface, this only sets where to connect to
                        $steps[] = [fn () => $this->os->addPeer($iface, $this->peerSection($peer)), null];
                    }
                }
            }

            $saved = $this->rewriteConf($link_name, $conf, $iface, peers: fn (array $peers) => $this->putPeer($peers, $peer));
            $this->applyLive($link_name, $conf, $steps);
            if ($reroute) {
                $this->restartOrRevert($link_name, $conf);
            }

            // The peer as it is saved now, with what it has of its own
            return $this->peerInfo(array_find($saved, fn (array $p) => $p['public_key'] === $pubkey), $link->address6, $link);
        });
    }

    /**
     * Give a peer new keys: a new key pair and preshared key, for when its config got into the
     * wrong hands. Everything else stays. Its public key is what it is known by, so that changes:
     * the old client config stops working, and the new one (with the new private key) comes back.
     */
    public function rekeyPeer(string $link_name, string $pubkey): PeerInfo
    {
        [$link_name, $pubkey] = $this->peerAddress($link_name, $pubkey);

        return $this->withLock(function () use ($link_name, $pubkey) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw NotFoundException::link($link_name);
            }

            $target = $this->findPeer($link, $pubkey);
            if ($target === null) {
                throw NotFoundException::peer($pubkey);
            }
            $conf = $this->managedConf($link_name);

            $privkey = $this->keys->genkey();
            $keys = ['public_key' => $this->keys->pubkey($privkey), 'preshared_key' => $this->keys->genpsk()];

            // The new private key first: the peer is never there without its key
            $this->os->writeClientConfig($link_name, KeyManager::pubkeyToSafe($keys['public_key']), ConfigBuilder::clientKeyFile($privkey));

            try {
                // In its place in the config, with everything saved with it
                $saved = $this->rewriteConf($link_name, $conf, $iface, peers: fn (array $peers) => array_map(
                    fn (array $p) => $p['public_key'] === $pubkey ? [...$p, ...$keys] : $p,
                    $peers,
                ));
                $peer = array_find($saved, fn (array $p) => $p['public_key'] === $keys['public_key']);
                // The traffic counted so far was the old key's
                $peer = array_diff_key($peer, array_flip(['endpoint', 'latest_handshake', 'transfer_rx', 'transfer_tx']));

                if ($iface !== null && $target->enabled) {
                    // After the config, which is rewritten from the live peers: the old key was still
                    // there. The new one first: it takes the allowed IPs over, and if it can't be
                    // added (its remote doesn't resolve), the old one is still there as it was.
                    $old = [...$peer, 'public_key' => $pubkey, 'preshared_key' => $target->preshared_key];
                    $this->applyLive($link_name, $conf, [
                        [fn () => $this->os->addPeer($iface, $this->peerSection($peer)), function () use ($iface, $keys, $old) {
                            $this->os->removePeer($iface, $keys['public_key']);
                            $this->os->addPeer($iface, $this->peerSection($old)); // its allowed IPs back
                        }],
                        [fn () => $this->os->removePeer($iface, $pubkey), null],
                    ]);
                }
            } catch (\Throwable $e) {
                $this->forgetKey($link_name, $keys['public_key']);

                throw $e;
            }

            try {
                $this->os->deleteClientConfig($link_name, KeyManager::pubkeyToSafe($pubkey));
            } catch (CommandFailedException $e) {
                throw new SystemException("Peer {$pubkey} has new keys and is now {$keys['public_key']}, but its old stored private key could not be deleted: {$e->getMessage()}", 0, $e);
            }

            return $this->peerInfo($peer, $link->address6, $link, $privkey, reveal: true);
        });
    }

    /**
     * A peer's remote, validated, whose host resolves now if it is a name: wg resolves it when the
     * link starts, and a name that doesn't resolve keeps the whole link from starting (wg-quick
     * fails on it). Checked when it is set, so a typo is a 422 now, not a link that won't start.
     */
    protected function resolvableRemote(string $remote): string
    {
        $remote = $this->validator->remote($remote);
        $host = substr($remote, 0, strrpos($remote, ':'));
        if (! str_starts_with($host, '[') && filter_var($host, FILTER_VALIDATE_IP) === false && ! $this->os->resolves($host)) {
            throw new InvalidArgumentException("{$host} doesn't resolve: a link doesn't start with a peer whose name doesn't resolve. Check the name, or give an address.");
        }

        return $remote;
    }

    /**
     * Validate the settings that get written into config files, when present. Returns them as
     * they are written: lists as `a, b`, and an empty dns, keepalive, allowed_ips or destinations
     * as null ("the default").
     */
    protected function validateSettings(array $settings): array
    {
        foreach (['dns', 'keepalive', 'allowed_ips'] as $field) {
            if (($settings[$field] ?? null) === '') {
                $settings[$field] = null;
            }
        }

        if (isset($settings['dns'])) {
            $settings['dns'] = $this->validator->validateDns((string) $settings['dns']);
        }
        if (isset($settings['allowed_ips'])) {
            $settings['allowed_ips'] = $this->validator->validateAllowedIps((string) $settings['allowed_ips']);
        }
        if (isset($settings['keepalive'])) {
            $this->validator->validateKeepalive((int) $settings['keepalive']);
        }
        if (isset($settings['ifout'])) {
            $this->validator->validateOutboundInterface((string) $settings['ifout']);
        }
        // A link's destinations: none (null, '') is anywhere
        if (array_key_exists('destinations', $settings)) {
            $settings['destinations'] = in_array($settings['destinations'], [null, ''], true)
                ? null
                : implode(', ', $this->validator->destinations((string) $settings['destinations']));
        }

        return $settings;
    }

    // ─── Backup and restore ──────────────────────────────────────────

    /**
     * Everything needed to recreate every link: its config (with all keys), whether it is running,
     * and the stored client configs of its peers. `unmanaged` names what a hand-written config has
     * that the app doesn't write: a restore rebuilds configs, so it can't take such a link.
     *
     * @return array<string, array{conf: string, up: bool, clients: array<string, string>, unmanaged: list<string>}>
     */
    public function exportLinks(): array
    {
        $links = [];
        foreach ($this->os->listConfigNames() as $name) {
            $link = $this->withLock(function () use ($name) {
                $conf = $this->os->readConfig($name);
                if ($conf === null) {
                    return null;
                }

                $clients = [];
                foreach ($this->configBuilder->parseConfContent($conf)['peers'] as $peer) {
                    if (! KeyManager::isKey($peer['PublicKey'] ?? '')) {
                        continue;
                    }
                    $safe = KeyManager::pubkeyToSafe($peer['PublicKey']);
                    if (($client = $this->os->readClientConfig($name, $safe)) !== null) {
                        $clients[$safe] = $client;
                    }
                }

                return ['conf' => $conf, 'up' => $this->isRunning($name), 'clients' => $clients, 'unmanaged' => $this->unmanagedSettings($conf)];
            });
            if ($link !== null) {
                $links[$name] = $link;
            }
        }

        return $links;
    }

    /**
     * Why a backed-up link can't be restored here (empty: it can): its config is invalid or has
     * settings the app doesn't manage, another network interface has its name, or it clashes
     * with the links that stay. restoreLink() checks the same things, so a restore can decide
     * everything before it changes anything.
     *
     * @param  list<string>  $ignore  links that won't be there (about to be replaced)
     * @return list<string>
     */
    public function restoreProblems(string $name, string $conf, array $ignore = []): array
    {
        try {
            $plan = $this->restorePlan($name, $conf);
        } catch (InvalidArgumentException|ConflictException $e) {
            return [$e->getMessage()];
        }

        $problems = [];
        if (! in_array($name, $this->listLinks(), true)) {
            if (in_array($name, $this->os->networkInterfaces(), true)) {
                $problems[] = "A network interface named {$name} already exists";
            }
        } elseif (! $this->os->configExists($name)) {
            // Replacing it would mean stopping an interface this app didn't start
            $problems[] = $this->withoutConfig($name)->getMessage();
        }
        $others = array_diff_key($this->otherLinks($name), array_flip($ignore));

        return [
            ...$problems,
            ...$this->clashes($plan['port'], $plan['address'], $others, $plan['address6'], $plan['networks']),
            ...$this->routeProblems($plan['networks'], $plan['allow_default_route'], $plan['allow_own_networks']),
        ];
    }

    /**
     * Recreate a link from an exported config, for this server: the config is rebuilt by this
     * OS's driver (hooks, helper path), a missing outbound interface falls back to the default
     * route's, and its endpoint (where its clients connect) stays as backed up unless $endpoint
     * points it elsewhere (keeping per-peer
     * overrides).
     *
     * With $replace it takes the place of an existing link of that name, which is only touched
     * once the new config has passed every check and the helper has accepted it.
     *
     * A restored link that doesn't start stays, stopped: its keys and client configs are what the
     * restore was for. The error comes back as `start_error`.
     *
     * @param  array<string, string>  $clients  safe pubkey => client config
     * @return array{ifout: array{0: ?string, 1: string}|null, clients: int, start_error: ?string}
     */
    public function restoreLink(string $name, string $conf, array $clients, bool $up, bool $replace = false, ?string $endpoint = null): array
    {
        $plan = $this->restorePlan($name, $conf);
        $endpoint = $endpoint === null || $endpoint === '' ? null : $this->validator->endpoint($endpoint);

        return $this->withLock(function () use ($name, $plan, $clients, $up, $replace, $endpoint) {
            ['meta' => $meta, 'address' => $address, 'address6' => $address6, 'peers' => $peers] = $plan;
            $clients = array_filter($clients, 'is_string');

            $exists = in_array($name, $this->listLinks(), true);
            if ($exists && ! $replace) {
                throw new ConflictException("Link already exists: {$name}");
            }
            $old = $exists ? ($this->os->readConfig($name) ?? throw $this->withoutConfig($name)) : null;
            $system_interfaces = $this->os->networkInterfaces();
            if (! $exists && in_array($name, $system_interfaces, true)) {
                throw new ConflictException("A network interface named {$name} already exists");
            }
            $this->assertNoClash($plan['port'], $address, $this->otherLinks($name), $address6, $plan['networks']);
            if (($problems = $this->routeProblems($plan['networks'], $plan['allow_default_route'], $plan['allow_own_networks'])) !== []) {
                throw new ConflictException($problems[0]);
            }

            $ifout = $meta['ifout'] ?? null;
            $moved = null;
            if ($ifout === null || ! in_array($ifout, $system_interfaces, true)) {
                $moved = [$ifout, $this->os->defaultOutboundInterface()];
                $ifout = $moved[1];
            }

            $endpoint ??= $meta['endpoint'] ?? null;
            $content = $this->buildConf($plan['interface'], array_merge($meta, [
                'address' => $address,
                'address6' => $address6,
                'port' => $plan['port'],
                'ifout' => $ifout,
                'endpoint' => $endpoint,
            ]), $peers);

            // The peers' private keys first, as anywhere: a peer is never there without its key.
            // (Their client configs are built from them, for this server.)
            $safe_keys = fn (array $peers) => array_map(fn (array $peer) => KeyManager::pubkeyToSafe($peer['public_key']), array_filter($peers, fn (array $peer) => KeyManager::isKey($peer['public_key'])));
            $keys = [];
            foreach ($peers as $peer) {
                $privkey = KeyManager::isKey($peer['public_key']) ? ConfigBuilder::clientPrivateKey($clients[KeyManager::pubkeyToSafe($peer['public_key'])] ?? null) : null;
                if ($privkey !== null) {
                    $keys[KeyManager::pubkeyToSafe($peer['public_key'])] = $privkey;
                }
            }
            $restored_peers = $safe_keys($peers);
            $old_peers = $old === null ? [] : $safe_keys($this->confPeers($this->configBuilder->parseConfContent($old)['peers']));
            // Best effort: a key without a peer opens nothing
            $forget = function (array $safe) use ($name) {
                foreach ($safe as $key) {
                    try {
                        $this->os->deleteClientConfig($name, $key);
                    } catch (CommandFailedException) {
                    }
                }
            };
            foreach ($keys as $safe => $privkey) {
                $this->os->writeClientConfig($name, $safe, ConfigBuilder::clientKeyFile($privkey));
            }

            // A link being replaced is untouched so far (but for the keys of peers it shares with
            // the restored one: the same keys), and stays so if the helper refuses the new config:
            // that is checked before it takes the old one's place
            $was_running = $exists && $this->runtimeInterface($name) !== null;
            try {
                $this->os->writeConfig($name, $content);
            } catch (\Throwable $e) {
                $forget(array_diff(array_keys($keys), $old_peers));

                throw $e;
            }

            if ($old !== null) {
                try {
                    $this->os->stopInterface($name);
                } catch (\Throwable $e) {
                    // Only a running link must stop (as in deleteLink). It still runs: its own config again
                    if ($was_running) {
                        $this->os->writeConfig($name, $old);
                        $forget(array_diff(array_keys($keys), $old_peers));

                        throw $e;
                    }
                }
                $this->os->clearFirewall($name);
                // The keys of the peers of the link it replaces that the restored one doesn't have
                $forget(array_diff($old_peers, $restored_peers));
            }
            $restored = count($keys);

            $start_error = null;
            if ($up) {
                try {
                    $this->assertRemotesResolve($name);
                    $this->os->startInterface($name);
                } catch (\Throwable $e) {
                    // Half started or not at all: down, and not coming up at boot
                    try {
                        $this->os->stopInterface($name);
                    } catch (\Throwable) {
                    }
                    $this->os->clearFirewall($name);
                    $start_error = $e->getMessage();
                }
            }

            return ['ifout' => $moved, 'clients' => $restored, 'start_error' => $start_error, 'endpoint' => $endpoint];
        });
    }

    /**
     * A backed-up config, checked and taken apart for restoreLink(). Throws when it can't be
     * restored: an invalid name, address, port or setting, or lines the app doesn't write.
     *
     * @return array{interface: array, meta: array, address: string, address6: ?string, port: int, peers: list<array>, networks: list<string>, allow_default_route: bool, allow_own_networks: bool}
     */
    protected function restorePlan(string $name, string $conf): array
    {
        $this->validator->validateInterfaceName($name);
        $this->assertManaged($name, $conf);

        $parsed = $this->configBuilder->parseConfContent($conf);
        $meta = $parsed['metadata'];
        // As it was: an existing link's address isn't held to what a new one must be
        $address = $this->validator->validateCidr($meta['address'] ?? trim(explode(',', $parsed['interface']['Address'] ?? '')[0]));
        $address6 = isset($meta['address6']) ? $this->validator->address6($meta['address6'], $address) : null;
        $port = (int) ($parsed['interface']['ListenPort'] ?? 0);
        $this->validator->validatePort($port);
        $this->validateSettings(['dns' => $meta['dns'] ?? null, 'keepalive' => $meta['keepalive'] ?? null, 'allowed_ips' => $meta['allowed_ips'] ?? null, 'destinations' => $meta['destinations'] ?? null]);

        $peers = $this->confPeers($parsed['peers']);
        // Networks behind its peers need routes too, which no other link may have
        $networks = array_merge([], ...array_map(fn (array $peer) => IpAllocator::networksOf($peer['allowed_ips'], $address6), $peers));

        return ['interface' => $parsed['interface'], 'meta' => $meta, 'address' => $address, 'address6' => $address6, 'port' => $port, 'peers' => $peers, 'networks' => $networks,
            'allow_default_route' => ($meta['allow_default_route'] ?? 'false') === 'true', 'allow_own_networks' => ($meta['allow_own_networks'] ?? 'false') === 'true'];
    }

    // ─── Runtime state ───────────────────────────────────────────────

    /**
     * The OS interface of a running link (utunN on macOS), or null when it is down.
     */
    protected function runtimeInterface(string $name): ?string
    {
        if (! $this->isLinkName($name)) {
            return null; // No link has such a name: nothing to ask the host
        }

        $iface = $this->os->resolveInterface($name);

        return in_array($iface, $this->runningInterfaces(), true) ? $iface : null;
    }

    protected function runningInterfaces(): array
    {
        return $this->os->runningInterfaces();
    }

    protected function isLinkName(string $name): bool
    {
        try {
            $this->validator->validateInterfaceName($name);

            return true;
        } catch (InvalidArgumentException) {
            return false;
        }
    }

    protected function loadLink(string $name, ?string $iface): ?InterfaceInfo
    {
        return $iface !== null
            ? $this->getLinkFromRuntime($name, $iface)
            : $this->getLinkFromConfig($name);
    }

    protected function getLinkFromRuntime(string $name, string $iface): ?InterfaceInfo
    {
        try {
            $output = $this->os->interfaceDump($iface);
        } catch (CommandFailedException $e) {
            // Stopped since it was listed: then it is what its config says. Anything else is a
            // read that failed (sudo, the helper, wg), never a link that isn't there.
            if (in_array($iface, $this->runningInterfaces(), true)) {
                throw $e;
            }

            return $this->getLinkFromConfig($name);
        }
        if ($output === '') {
            throw new SystemException("The state of interface {$iface} could not be read: wg show answered nothing.");
        }

        $lines = explode("\n", $output);

        // Line 1: private_key, public_key, listen_port, fwmark (tab-separated)
        $iface_parts = explode("\t", $lines[0]);
        $private_key = $iface_parts[0] ?? '';
        $public_key = $private_key !== '' && $private_key !== '(none)' ? $this->keys->pubkey($private_key) : '';

        // Names and disabled peers only live in the config
        $content = $this->os->readConfig($name);
        $parsed = $this->configBuilder->parseConfContent($content ?? '');
        $meta = $parsed['metadata'];
        $peers = $this->livePeers($this->parseDumpPeers($lines), $this->confPeers($parsed['peers']));

        return new InterfaceInfo(
            name: $name,
            public_key: $public_key,
            listen_port: (int) ($iface_parts[2] ?? 0),
            address: $this->os->interfaceAddress($iface) ?? $meta['address'] ?? '(none)',
            ifout: $meta['ifout'] ?? $this->os->defaultOutboundInterface(),
            forward: ($meta['forward'] ?? 'false') === 'true',
            nat: ($meta['nat'] ?? 'false') === 'true',
            up: true,
            peers: array_map(fn (array $p) => $this->peerInfo($p, $meta['address6'] ?? null), $peers),
            interface: $iface,
            address6: $meta['address6'] ?? null,
            dns: $meta['dns'] ?? null,
            keepalive: isset($meta['keepalive']) ? (int) $meta['keepalive'] : null,
            allowed_ips: $meta['allowed_ips'] ?? null,
            mtu: isset($parsed['interface']['MTU']) ? (int) $parsed['interface']['MTU'] : null,
            inbound: self::flag($meta, 'inbound'),
            allow_default_route: self::flag($meta, 'allow_default_route'),
            allow_own_networks: self::flag($meta, 'allow_own_networks'),
            endpoint: $meta['endpoint'] ?? null,
            destinations: $meta['destinations'] ?? null,
            // No config here: an interface something else started
            managed: $content !== null && $this->unmanagedSettings($content) === [],
        );
    }

    /** A link setting that is true or false in its metadata (absent: false). */
    protected static function flag(array $meta, string $key): bool
    {
        return ($meta[$key] ?? 'false') === 'true';
    }

    protected function getLinkFromConfig(string $name): ?InterfaceInfo
    {
        $content = $this->isLinkName($name) ? $this->os->readConfig($name) : null;

        return $content === null ? null : $this->linkFromConf($name, $content);
    }

    /** A stopped link as a config has it: the one on disk, or one that is about to be (an adoption's dry run). */
    protected function linkFromConf(string $name, string $content): InterfaceInfo
    {
        $parsed = $this->configBuilder->parseConfContent($content);
        $metadata = $parsed['metadata'];
        $interface = $parsed['interface'];

        $private_key = $interface['PrivateKey'] ?? '';

        return new InterfaceInfo(
            name: $name,
            // A hand-written config's key may be no key at all: then it has no public key either
            public_key: KeyManager::isKey($private_key) ? $this->keys->pubkey($private_key) : '',
            listen_port: (int) ($interface['ListenPort'] ?? 0),
            address: $metadata['address'] ?? trim(explode(',', $interface['Address'] ?? '(none)')[0]),
            ifout: $metadata['ifout'] ?? $this->os->defaultOutboundInterface(),
            forward: ($metadata['forward'] ?? 'false') === 'true',
            nat: ($metadata['nat'] ?? 'false') === 'true',
            up: false,
            peers: array_map(fn (array $p) => $this->peerInfo($p, $metadata['address6'] ?? null), $this->confPeers($parsed['peers'])),
            address6: $metadata['address6'] ?? null,
            dns: $metadata['dns'] ?? null,
            keepalive: isset($metadata['keepalive']) ? (int) $metadata['keepalive'] : null,
            allowed_ips: $metadata['allowed_ips'] ?? null,
            mtu: isset($interface['MTU']) ? (int) $interface['MTU'] : null,
            inbound: self::flag($metadata, 'inbound'),
            allow_default_route: self::flag($metadata, 'allow_default_route'),
            allow_own_networks: self::flag($metadata, 'allow_own_networks'),
            endpoint: $metadata['endpoint'] ?? null,
            destinations: $metadata['destinations'] ?? null,
            managed: $this->unmanagedSettings($content) === [],
        );
    }

    // ─── Clash checks ────────────────────────────────────────────────

    /**
     * Listen port and address of every other link, from their configs.
     *
     * @return array<string, array{port: int, address: string, address6: string, peers: list<string>}>
     */
    protected function otherLinks(string $name): array
    {
        $links = [];
        foreach ($this->os->listConfigNames() as $other) {
            if ($other === $name || ($content = $this->os->readConfig($other)) === null) {
                continue;
            }
            $parsed = $this->configBuilder->parseConfContent($content);
            $links[$other] = [
                'port' => (int) ($parsed['interface']['ListenPort'] ?? 0),
                'address' => $parsed['metadata']['address'] ?? trim(explode(',', $parsed['interface']['Address'] ?? '')[0]),
                'address6' => $parsed['metadata']['address6'] ?? '',
                // Every allowed IP of its peers: tunnel addresses and networks behind them
                'peers' => array_merge(...array_map(
                    fn (array $p) => array_map('trim', explode(',', $p['AllowedIPs'] ?? '')),
                    $parsed['peers'],
                ) ?: [[]]),
            ];
        }

        return $links;
    }

    /**
     * A random port in 33000-65000 that no other link listens on.
     */
    protected function freePort(array $others): int
    {
        $used = array_column($others, 'port');
        for ($attempt = 0; $attempt < 100; $attempt++) {
            $port = random_int(33000, 65000);
            if (! in_array($port, $used, true)) {
                return $port;
            }
        }

        throw new ConflictException('No free listen port found.');
    }

    /**
     * Why a link with this port and these addresses can't live next to $others (empty: it can).
     * Two links can't listen on the same port or route overlapping subnets (of either family),
     * the networks behind their peers included: each route can only lead one way.
     *
     * @param  list<string>  $networks  networks behind the link's own peers
     * @return list<string>
     */
    protected function clashes(?int $port, ?string $address, array $others, ?string $address6 = null, array $networks = []): array
    {
        $problems = [];
        foreach ($others as $other => $settings) {
            if ($port !== null && $port === $settings['port']) {
                $problems[] = "Port {$port} is already used by link {$other}";
            }
            if ($address !== null && $settings['address'] !== '' && IpAllocator::overlaps($address, $settings['address'])) {
                $problems[] = "Subnet {$address} overlaps link {$other} ({$settings['address']})";
            }
            if ($address6 !== null && $settings['address6'] !== '' && IpAllocator::overlaps($address6, $settings['address6'])) {
                $problems[] = "Prefix {$address6} overlaps link {$other} ({$settings['address6']})";
            }

            // What its peers route besides their tunnel addresses (those are inside its subnet, checked above)
            $routed = array_filter($settings['peers'], fn (string $entry) => $entry !== ''
                && ! ($settings['address'] !== '' && IpAllocator::overlaps($entry, $settings['address']))
                && ! ($settings['address6'] !== '' && IpAllocator::overlaps($entry, $settings['address6'])));
            foreach ($routed as $network) {
                foreach (IpAllocator::isDefaultRoute($network) ? [] : array_filter([$address, $address6]) as $own) {
                    if (IpAllocator::overlaps($own, $network)) {
                        $problems[] = "{$own} overlaps {$network}, routed to a peer of link {$other}";
                    }
                }
            }
            foreach ($networks as $network) {
                foreach (array_filter([$settings['address'], $settings['address6'], ...$routed]) as $entry) {
                    if ($this->routesClash($network, $entry)) {
                        $problems[] = "{$network} overlaps {$entry} of link {$other}";
                    }
                }
            }
        }

        return $problems;
    }

    /**
     * Whether two routes (a network behind a peer, a link's subnet, another peer's network) can't
     * both be: they overlap. A default route is the least specific: what else is routed still goes
     * where it goes. Only another default route of the same family can't share it.
     */
    protected function routesClash(string $a, string $b): bool
    {
        return IpAllocator::isDefaultRoute($a) || IpAllocator::isDefaultRoute($b)
            ? IpAllocator::isDefaultRoute($a) && IpAllocator::isDefaultRoute($b) && IpAllocator::sameFamily($a, $b)
            : IpAllocator::overlaps($a, $b);
    }

    protected function assertNoClash(?int $port, ?string $address, array $others, ?string $address6 = null, array $networks = []): void
    {
        if (($problems = $this->clashes($port, $address, $others, $address6, $networks)) !== []) {
            throw new ConflictException($problems[0]);
        }
    }

    /**
     * Networks behind a peer can't overlap the link's own addresses, another peer's addresses or
     * networks, or another link's subnets and peers: each route can only lead to one peer. And
     * what would take the server's own traffic needs the link's and the server's leave
     * (routeProblems()).
     *
     * @param  list<string>  $networks
     * @param  string|null  $pubkey  the peer they're for, when it exists already
     */
    protected function assertNetworksFree(InterfaceInfo $link, array $networks, ?string $pubkey = null): void
    {
        if (($problems = $this->routeProblems($networks, $link->allow_default_route, $link->allow_own_networks)) !== []) {
            throw new InvalidArgumentException($problems[0]);
        }

        foreach ($networks as $network) {
            foreach (IpAllocator::isDefaultRoute($network) ? [] : array_filter([$link->address, $link->address6]) as $own) {
                if (IpAllocator::overlaps($network, $own)) {
                    throw new InvalidArgumentException("{$network} overlaps the link's own addresses ({$own}).");
                }
            }
            foreach ($link->peers as $peer) {
                foreach ($peer->public_key === $pubkey ? [] : array_map('trim', explode(',', (string) $peer->allowed_ips)) as $entry) {
                    if ($entry !== '' && $this->routesClash($network, $entry)) {
                        throw new ConflictException("{$network} overlaps {$entry} of peer ".($peer->name ?? $peer->public_key));
                    }
                }
            }
            foreach ($this->otherLinks($link->name) as $other => $settings) {
                foreach (array_filter([$settings['address'], $settings['address6'], ...$settings['peers']]) as $entry) {
                    if ($this->routesClash($network, $entry)) {
                        throw new ConflictException("{$network} overlaps {$entry} of link {$other}");
                    }
                }
            }
        }
    }

    /**
     * What of $networks (behind a link's peers) would take the server's own traffic without the
     * leave to: a default route, or a network that covers an address the server uses itself (one
     * of its interfaces', its gateway: the server would lose its network). Each needs the link's
     * setting (allow_default_route, allow_own_networks) and the server's policy, which wg:install
     * sets and the root helper enforces too.
     *
     * @param  list<string>  $networks
     * @return list<string> what is wrong, one line per network
     */
    protected function routeProblems(array $networks, bool $allow_default_route, bool $allow_own_networks): array
    {
        $policy = null;
        $server = function (string $key) use (&$policy): bool {
            $policy ??= $this->os->routePolicy();

            return $policy[$key];
        };
        $why = fn (string $what, string $setting, string $option) => "{$what} Only on a link with {$setting}, and on a server that allows it (php artisan wg:install --{$option}=true).";

        $problems = [];
        foreach (array_filter($networks, IpAllocator::isDefaultRoute(...)) as $network) {
            if (! $allow_default_route || ! $server('allow_default_route')) {
                $problems[] = $why("{$network} is a default route: the server's own traffic would go to the peer.", 'allow_default_route', 'allow-default-route');
            }
        }
        foreach ($this->coveredOwnAddresses($networks) as $network => $address) {
            if (! $allow_own_networks || ! $server('allow_own_networks')) {
                $problems[] = $why("{$network} covers {$address}, an address this server uses itself (its own or its gateway's): routed to a peer, the server would lose its network.", 'allow_own_networks', 'allow-own-networks');
            }
        }

        return $problems;
    }

    /**
     * A link can only allow its peers what the server's policy allows (asked only when it matters).
     */
    protected function assertPolicyAllows(bool $default_route, bool $own_networks): void
    {
        if (! $default_route && ! $own_networks) {
            return;
        }
        $policy = $this->os->routePolicy();
        foreach (['allow_default_route' => $default_route, 'allow_own_networks' => $own_networks] as $setting => $asked) {
            if ($asked && ! $policy[$setting]) {
                throw new ConflictException("This server doesn't let links allow that ({$setting}): php artisan wg:install --".str_replace('_', '-', $setting).'=true sets its policy.');
            }
        }
    }

    /**
     * Networks that cover an address the server needs itself: one of its interfaces', or its
     * default gateway. Routed to a peer, that traffic would go into the tunnel instead, and the
     * server would be cut off from its own network. (A link's own addresses are checked apart,
     * and a default route, which covers everything, is a case of its own: routeProblems().)
     *
     * @param  list<string>  $networks
     * @return array<string, string> network => an address of the server's own it covers
     */
    protected function coveredOwnAddresses(array $networks): array
    {
        $networks = array_filter($networks, fn (string $network) => ! IpAllocator::isDefaultRoute($network));
        if ($networks === []) {
            return [];
        }

        $own = array_filter($this->os->ownAddresses(), fn (string $address) => filter_var($address, FILTER_VALIDATE_IP) !== false);
        $links = array_merge(...array_values(array_map(
            fn (array $settings) => [$settings['address'], $settings['address6']],
            $this->otherLinks(''),
        )) ?: [[]]);
        // What a link has is refused as a clash, with the link's name
        $own = array_filter($own, fn (string $address) => ! array_any(array_filter($links), fn (string $cidr) => IpAllocator::overlaps($address, $cidr)));

        $covered = [];
        foreach ($networks as $network) {
            foreach ($own as $address) {
                if (IpAllocator::overlaps($network, $address)) {
                    $covered[$network] = $address;

                    break;
                }
            }
        }

        return $covered;
    }

    /**
     * Before the app starts (or restarts) a link: the remote name of every enabled peer resolves
     * now. wg-quick resolves them as it starts, retrying one that doesn't for minutes (past the
     * app's timeout) and failing the whole link on one that can't. (At boot systemd starts links,
     * and waits as long as it takes.)
     *
     * @param  list<array>|null  $peers  the peers it is about to start with, when its config isn't written yet
     */
    protected function assertRemotesResolve(string $name, ?array $peers = null): void
    {
        foreach ($peers ?? $this->confPeers($this->configBuilder->parseConfContent($this->os->readConfig($name) ?? '')['peers']) as $peer) {
            if (! $peer['enabled'] || $peer['remote'] === null) {
                continue;
            }
            $host = substr($peer['remote'], 0, (int) strrpos($peer['remote'], ':'));
            if (! str_starts_with($host, '[') && filter_var($host, FILTER_VALIDATE_IP) === false && ! $this->os->resolves($host)) {
                throw new ConflictException("{$host}, the remote of peer ".($peer['name'] ?? $peer['public_key'])." of link {$name}, doesn't resolve now: the link wouldn't start. Fix the name, or change or take out the peer's remote.");
            }
        }
    }

    /**
     * Stop and start a running link, so wg-quick applies its config (routes included). PostUp
     * installs the firewall rules again.
     */
    protected function restart(string $name): void
    {
        $this->os->stopInterface($name);
        $this->os->clearFirewall($name);
        $this->os->startInterface($name);
    }

    /**
     * restart() for a config change: when the link doesn't come up with it, $conf (the config
     * before the change) goes back and the link runs again as it did.
     */
    protected function restartOrRevert(string $name, string $conf): void
    {
        try {
            $this->assertRemotesResolve($name);
            $this->restart($name);
        } catch (\Throwable $e) {
            throw $this->revert($name, $conf, true, $e);
        }
    }

    /**
     * Undo a config change that the host didn't take (the link didn't stop, start, or take its
     * firewall rules): write the previous config back and put the link in the state it was in,
     * so a change that fails doesn't leave the link down. Returns the exception to throw.
     */
    protected function revert(string $name, string $conf, bool $was_running, \Throwable $e): SystemException
    {
        try {
            $this->os->writeConfig($name, $conf);
            $iface = $this->runtimeInterface($name);
            if ($was_running && $iface !== null) {
                // It never went down: only its rules may have changed
                $this->os->applyFirewall($name, $iface);
            } else {
                // Down, or half started: also keeps a link that was down from starting at boot
                $this->os->stopInterface($name);
                $this->os->clearFirewall($name);
                if ($was_running) {
                    $this->os->startInterface($name);
                }
            }
        } catch (\Throwable) {
            return $this->failedChange($name, $e, undone: false);
        }

        return $this->failedChange($name, $e, undone: true);
    }

    /**
     * Change peers on a running link's interface, after its config was rewritten to the new state
     * (the config is rewritten from the live peers: a peer taken off the interface before that
     * would lose its place, and what is saved with it). A step the host doesn't take (a remote
     * that doesn't resolve, sudo failing) undoes the change: the config goes back to $conf, and
     * the steps done so far are undone, last first. Else the next rewrite from the live peers
     * would drop a peer that is off the interface, or keep half of the change.
     *
     * @param  list<array{0: Closure(): mixed, 1: (Closure(): mixed)|null}>  $steps  each with its undo
     */
    protected function applyLive(string $name, string $conf, array $steps): void
    {
        $done = [];
        try {
            foreach ($steps as [$step, $undo]) {
                $step();
                $done[] = $undo;
            }
        } catch (\Throwable $e) {
            try {
                $this->os->writeConfig($name, $conf);
                foreach (array_reverse(array_filter($done)) as $undo) {
                    $undo();
                }
            } catch (\Throwable) {
                throw $this->failedChange($name, $e, undone: false);
            }

            throw $this->failedChange($name, $e, undone: true);
        }
    }

    protected function failedChange(string $name, \Throwable $e, bool $undone): SystemException
    {
        return new SystemException($undone
            ? "The change to link {$name} could not be applied and was undone: {$e->getMessage()}"
            : "The change to link {$name} could not be applied, and undoing it failed too (check the link with wg:link {$name}): {$e->getMessage()}", 0, $e);
    }

    /**
     * Delete the stored private key of a peer that didn't make it (a new one, or new keys), unless
     * the link has it after all: in its config or on its interface (undoing the change failed).
     * A peer is never left without its key; a key without a peer opens nothing, so this is best
     * effort.
     */
    protected function forgetKey(string $link, string $pubkey): void
    {
        try {
            // Asked anew: a restart that was undone gives a macOS link another utunN
            $iface = $this->runtimeInterface($link);
            $conf = $this->os->readConfig($link);
            $kept = $conf === null
                || in_array($pubkey, array_column($this->confPeers($this->configBuilder->parseConfContent($conf)['peers']), 'public_key'), true)
                || ($iface !== null && in_array($pubkey, array_column($this->dumpPeers($iface), 'public_key'), true));
            if (! $kept) {
                $this->os->deleteClientConfig($link, KeyManager::pubkeyToSafe($pubkey));
            }
        } catch (\Throwable) {
        }
    }

    /**
     * The IPv6 address for a link: null (none; also '' and 'none'), 'auto' (a random unique local
     * /64, using the IPv4 address's host number), or a validated address and prefix.
     */
    protected function resolveAddress6(?string $value, string $address): ?string
    {
        if ($value === null || $value === '' || $value === 'none') {
            return null;
        }
        if ($value === 'auto') {
            [$ip] = explode('/', $address, 2);
            $prefix = IpAllocator::randomUlaPrefix();

            return IpAllocator::hostAt($prefix, IpAllocator::hostIndex($ip, $address) ?? 1).'/64';
        }

        return $this->validator->address6($value, $address);
    }

    /**
     * Peers with their tunnel addresses for the link's new addresses. The IPv6 one mirrors the
     * IPv4 host number in the link's prefix, so the mirrored /128 of the old prefix is replaced
     * (or dropped). The IPv4 one stays, unless the peers move along with the link ($moved_from,
     * its old address): then each keeps its host number in the new subnet. Other allowed IPs stay.
     *
     * @param  list<array{public_key: string, allowed_ips: string}>  $peers
     */
    protected function readdressPeers(array $peers, string $address, ?string $address6, ?string $old_address6, ?string $moved_from = null): array
    {
        return array_map(function (array $peer) use ($address, $address6, $old_address6, $moved_from) {
            $ip = IpAllocator::tunnelIp($peer['allowed_ips']);
            if ($ip === null) {
                return $peer;
            }

            $others = array_filter(array_map('trim', explode(',', $peer['allowed_ips'])), fn (string $entry) => $entry !== "{$ip}/32"
                && ! ($old_address6 !== null && str_ends_with($entry, '/128') && IpAllocator::overlaps($entry, $old_address6)));
            $ip = $moved_from === null ? $ip : $this->movedIp($ip, $moved_from, $address);

            return array_merge($peer, ['allowed_ips' => implode(', ', [IpAllocator::peerAllowedIps($ip, $address, $address6), ...$others])]);
        }, $peers);
    }

    /**
     * A peer's address when it moves along with its link: the same host number in the new subnet.
     */
    protected function movedIp(string $ip, string $from, string $to): string
    {
        $host = IpAllocator::hostIndex($ip, $from)
            ?? throw new InvalidArgumentException("Peer {$ip} is not inside the link's address {$from}, so it can't move along. Give it an address in it first (its `ip`).");

        try {
            return IpAllocator::hostAt($to, $host);
        } catch (InvalidArgumentException) {
            throw new InvalidArgumentException("Peer {$ip} can't move along: its host number {$host} doesn't fit {$to}.");
        }
    }

    /**
     * A link's addresses can only change where its peers' tunnel addresses still fit: inside the
     * IPv4 subnet, on a host address that isn't the link's, and not mirrored onto the link's own
     * IPv6 address. With $moved_from (the link's old address) the peers move along first.
     */
    protected function assertPeersFit(string $name, string $address, ?string $address6 = null, ?string $moved_from = null): void
    {
        [$link_ip, $mask] = explode('/', $address, 2);
        $link_ip6 = $address6 === null ? null : explode('/', $address6, 2)[0];
        $network = ip2long($link_ip) & ((-1 << (32 - (int) $mask)) & 0xFFFFFFFF);
        $unusable = (int) $mask <= 30 ? [$network, $network | ((1 << (32 - (int) $mask)) - 1)] : [];

        foreach ($this->loadLink($name, $this->runtimeInterface($name))?->peers ?? [] as $peer) {
            $ip = IpAllocator::tunnelIp($peer->allowed_ips);
            if ($ip === null) {
                continue;
            }
            if ($moved_from !== null) {
                $ip = $this->movedIp($ip, $moved_from, $address);
            } elseif (! $this->validator->ipInRange($ip, $address)) {
                throw new InvalidArgumentException("Peer {$ip} would not fit the new address {$address}. To move the link's peers along (each keeps its host number, and every client needs its new config), pass move_peers (--move-peers).");
            }
            if ($ip === $link_ip || in_array(ip2long($ip), $unusable, true)) {
                throw new InvalidArgumentException("Peer {$ip} would not fit the new address {$address}: that is the link's own, the network or the broadcast address. Move the peer first (its `ip`).");
            }
            if ($address6 !== null && IpAllocator::mirror($ip, $address, $address6) === $link_ip6) {
                throw new InvalidArgumentException("Peer {$ip} would get the link's IPv6 address {$link_ip6}. Move the peer first (its `ip`).");
            }
            foreach (array_filter(array_map('trim', explode(',', (string) $peer->networks))) as $network_behind) {
                // (A default route holds the link's addresses too, but less specifically: no clash)
                foreach (IpAllocator::isDefaultRoute($network_behind) ? [] : array_filter([$address, $address6]) as $own) {
                    if (IpAllocator::overlaps($network_behind, $own)) {
                        throw new InvalidArgumentException("{$own} would overlap {$network_behind}, routed to peer {$ip}.");
                    }
                }
            }
        }
    }

    // ─── Config regeneration ─────────────────────────────────────────

    /**
     * Regenerate a link's .conf from $content, its current contents (as managedConf() returned
     * them), plus metadata overrides.
     *
     * Peers come from the live interface when $iface is given (what `wg` has, merged with what
     * only the config knows: see livePeers()), otherwise from the file itself. $peers transforms
     * that list into the new one; the live change follows (applyLive()).
     *
     * @return list<array> the peers as they were written
     */
    protected function rewriteConf(string $name, string $content, ?string $iface, array $overrides = [], ?Closure $peers = null): array
    {
        $parsed = $this->configBuilder->parseConfContent($content);
        $saved = $this->confPeers($parsed['peers']);
        $current = $iface !== null ? $this->livePeers($this->dumpPeers($iface), $saved) : $saved;
        $written = $peers !== null ? $peers($current) : $current;

        $this->os->writeConfig($name, $this->buildConf($parsed['interface'], array_merge($parsed['metadata'], $overrides), $written));

        return $written;
    }

    /**
     * A link's config from the [Interface] section of a parsed one, its metadata (with any
     * overrides, `port` among them) and its peers.
     */
    protected function buildConf(array $interface, array $meta, array $peers): string
    {
        return $this->configBuilder->buildConfFile(
            address: $meta['address'] ?? trim(explode(',', $interface['Address'] ?? '')[0]),
            privkey: $interface['PrivateKey'] ?? '',
            port: (int) ($meta['port'] ?? $interface['ListenPort'] ?? 0),
            ifout: $meta['ifout'] ?? $this->os->defaultOutboundInterface(),
            peers: $peers,
            dns: $meta['dns'] ?? null,
            keepalive: isset($meta['keepalive']) ? (int) $meta['keepalive'] : null,
            allowed_ips: $meta['allowed_ips'] ?? null,
            forward: ($meta['forward'] ?? 'false') === 'true',
            nat: ($meta['nat'] ?? 'false') === 'true',
            address6: $meta['address6'] ?? null,
            // An override (null: none any more), else what the config has
            mtu: array_key_exists('mtu', $meta) ? $meta['mtu'] : (isset($interface['MTU']) ? (int) $interface['MTU'] : null),
            inbound: self::flag($meta, 'inbound'),
            allow_default_route: self::flag($meta, 'allow_default_route'),
            allow_own_networks: self::flag($meta, 'allow_own_networks'),
            endpoint: $meta['endpoint'] ?? null,
            destinations: $meta['destinations'] ?? null,
        );
    }

    /**
     * A link's config before a change to it. Refuses what the app can't change without losing
     * something: a config with settings it doesn't write (see assertManaged()), and a WireGuard
     * interface that runs without a config here. Such an interface is listed and shown, but a
     * peer added to it would be gone at its next start, with a stored key nothing accounts for.
     */
    protected function managedConf(string $name): string
    {
        $content = $this->os->readConfig($name) ?? throw $this->withoutConfig($name);
        $this->assertManaged($name, $content, adoptable: true);

        return $content;
    }

    /**
     * What to throw for a link that has no config: it isn't there, or it is a WireGuard interface
     * something else started (wg-quick with a config elsewhere, `ip link`, another tool).
     */
    protected function withoutConfig(string $name): NotFoundException|ConflictException
    {
        return $this->runtimeInterface($name) === null
            ? NotFoundException::link($name)
            : new ConflictException("{$name} is a running WireGuard interface without a config here: this app can show it, but not change, stop or delete it. Manage it where it was started.", ErrorCode::UNMANAGED_INTERFACE);
    }

    /**
     * The .conf is always regenerated whole, so a hand-written one would lose whatever the app
     * doesn't write: Table, hooks of its own, a keepalive of a peer's own, comments. Such a config
     * can be read and deleted, but not changed: only adopted, which drops the hooks and comments
     * for good and refuses the rest (adoptLink()).
     *
     * @param  bool  $adoptable  it is a link's config here (not one in a backup): say how to adopt it
     */
    protected function assertManaged(string $name, string $content, bool $adoptable = false): void
    {
        $what = $this->unmanagedSettings($content);
        if ($what === []) {
            return;
        }

        $shown = implode(', ', array_slice($what, 0, 6)).(count($what) > 6 ? ', …' : '');

        throw new ConflictException(
            "Link {$name} has settings this app doesn't manage ({$shown}): a change made here would drop them, or break the link. Edit its config by hand"
                .($adoptable ? ", or adopt it: wgla link:adopt {$name} --dry-run (POST /link/{$name}/adopt with dry_run) shows what that keeps and drops." : '.'),
            ErrorCode::UNMANAGED_CONFIG,
        );
    }

    /**
     * What a config has that regenerating it would drop, named by key only (a line may hold a
     * secret): e.g. ['MTU', 'Endpoint', 'comments']. And what the app needs that it leaves out
     * ('no ListenPort': wg-quick picks a port at each start, and the rewrite would be refused).
     * Empty for a config the app can manage.
     *
     * @return list<string>
     */
    protected function unmanagedSettings(string $content): array
    {
        $parsed = $this->configBuilder->parseConfContent($content);
        // Any outbound interface will do here: this is about what a rewrite would leave out
        $rebuilt = $this->buildConf($parsed['interface'], $parsed['metadata'] + ['ifout' => 'none'], $this->confPeers($parsed['peers']));

        $what = [];
        foreach (['PrivateKey', 'Address', 'ListenPort'] as $key) {
            if (! isset($parsed['interface'][$key])) {
                $what[] = "no {$key}";
            }
        }
        foreach (ConfigBuilder::droppedLines($content, $rebuilt) as $line) {
            $what[] = match (true) {
                (bool) preg_match('/^([A-Za-z0-9]+) = /', $line, $m) => $m[1],
                str_starts_with($line, '#') => 'comments',
                default => 'other lines',
            };
        }

        return array_values(array_unique($what));
    }

    /**
     * Peers of a running interface. Throws rather than returning an empty list, so a failed
     * read can never be written back as "no peers".
     */
    protected function dumpPeers(string $iface): array
    {
        $output = $this->os->interfaceDump($iface);

        return $this->parseDumpPeers(explode("\n", $output));
    }

    /**
     * @param  string[]  $lines  `wg show <iface> dump` output; line 1 is the interface itself
     * @return list<array{public_key: string, allowed_ips: string, preshared_key?: string}>
     */
    protected function parseDumpPeers(array $lines): array
    {
        $peers = [];
        // Peer lines: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx, tx, keepalive
        foreach (array_slice($lines, 1) as $line) {
            $parts = explode("\t", $line);
            if (count($parts) < 4) {
                continue;
            }

            $peer = [
                'public_key' => $parts[0],
                // wg separates them with a bare comma; configs and the API use ", "
                'allowed_ips' => implode(', ', explode(',', $parts[3])),
                // Live stats (not written to the config)
                'endpoint' => ($parts[2] ?? '(none)') === '(none)' ? null : $parts[2],
                'latest_handshake' => (int) ($parts[4] ?? 0) ?: null,
                'transfer_rx' => (int) ($parts[5] ?? 0),
                'transfer_tx' => (int) ($parts[6] ?? 0),
            ];
            if ($parts[1] !== '(none)') {
                $peer['preshared_key'] = $parts[1];
            }
            $peers[] = $peer;
        }

        return $peers;
    }

    /**
     * @param  array  $sections  [Peer] sections from ConfigBuilder::parseConfContent()
     */
    protected function confPeers(array $sections): array
    {
        $peers = [];
        foreach ($sections as $section) {
            $peer = [
                'public_key' => $section['PublicKey'] ?? '',
                'allowed_ips' => $section['AllowedIPs'] ?? '',
                'enabled' => ! ($section['disabled'] ?? false),
                // Where the server connects to it. (`wg` reports where it last was, which may differ)
                'remote' => $section['Endpoint'] ?? null,
            ];
            // Its label and own client settings: comments in its section
            foreach (array_keys(ConfigBuilder::PEER_SETTINGS) as $field) {
                $peer[$field] = $section[$field] ?? null;
            }
            if (! empty($section['PresharedKey'])) {
                $peer['preshared_key'] = $section['PresharedKey'];
            }
            $peers[] = $peer;
        }

        return $peers;
    }

    /**
     * @param  InterfaceInfo|null  $link  given: the peer comes with its client config, built now
     * @param  string|null  $privkey  its private key when the caller has it, else the stored one
     * @param  bool  $reveal  also return the private key itself (a peer that was just created)
     */
    protected function peerInfo(array $peer, ?string $address6, ?InterfaceInfo $link = null, ?string $privkey = null, bool $reveal = false): PeerInfo
    {
        $networks = IpAllocator::networksOf($peer['allowed_ips'], $address6);

        $info = new PeerInfo(
            public_key: $peer['public_key'],
            preshared_key: $peer['preshared_key'] ?? null,
            allowed_ips: $peer['allowed_ips'],
            private_key: $reveal ? $privkey : null,
            endpoint: $peer['endpoint'] ?? null,
            latest_handshake: $peer['latest_handshake'] ?? null,
            transfer_rx: $peer['transfer_rx'] ?? null,
            transfer_tx: $peer['transfer_tx'] ?? null,
            name: $peer['name'] ?? null,
            enabled: $peer['enabled'] ?? true,
            networks: $networks === [] ? null : implode(', ', $networks),
            dns: $peer['dns'] ?? null,
            keepalive: isset($peer['keepalive']) ? (int) $peer['keepalive'] : null,
            client_allowed_ips: $peer['client_allowed_ips'] ?? null,
            remote: $peer['remote'] ?? null,
        );

        return $link === null ? $info : $info->with(client_config: $this->clientConfig($link, $info, $privkey));
    }

    /**
     * Peers of a running link: the live ones (from `wg show dump`), with what only the config
     * knows of them (name, own client settings), plus the disabled ones (only in the config), in
     * the config's order.
     *
     * @param  list<array>  $live
     * @param  list<array>  $saved  from confPeers()
     */
    protected function livePeers(array $live, array $saved): array
    {
        $live = array_column($live, null, 'public_key');
        $peers = [];
        foreach ($saved as $peer) {
            if (isset($live[$peer['public_key']])) {
                $peers[] = [...$live[$peer['public_key']], ...array_intersect_key($peer, ConfigBuilder::PEER_SETTINGS + ['remote' => true]), 'enabled' => true];
                unset($live[$peer['public_key']]);
            } elseif (! $peer['enabled']) {
                $peers[] = $peer;
            }
            // An enabled peer that isn't live any more was removed from the interface
        }

        return [...$peers, ...array_values($live)];
    }

    /**
     * $peers with $peer merged into the one with its public key, or appended.
     */
    protected function putPeer(array $peers, array $peer): array
    {
        foreach ($peers as $i => $existing) {
            if ($existing['public_key'] === $peer['public_key']) {
                $peers[$i] = array_merge($existing, $peer);

                return $peers;
            }
        }

        return [...$peers, $peer];
    }

    protected function findPeer(InterfaceInfo $link, string $pubkey): ?PeerInfo
    {
        foreach ($link->peers as $peer) {
            if ($peer->public_key === $pubkey) {
                return $peer;
            }
        }

        return null;
    }

    protected function peerSection(array $peer): string
    {
        return implode("\n", array_filter([
            '[Peer]',
            "PublicKey = {$peer['public_key']}",
            empty($peer['preshared_key']) ? null : "PresharedKey = {$peer['preshared_key']}",
            "AllowedIPs = {$peer['allowed_ips']}",
            empty($peer['remote']) ? null : "Endpoint = {$peer['remote']}",
            empty($peer['remote']) ? null : 'PersistentKeepalive = '.ConfigBuilder::REMOTE_KEEPALIVE,
        ]))."\n";
    }

    // ─── Locking ─────────────────────────────────────────────────────

    /**
     * One change at a time, across processes and across links: a link's port, subnet and routed
     * networks are checked against every other link's, so two changes to different links could
     * otherwise both pass a check that only one of them should. The lock directory is shared by
     * the CLI and the web server (unlike /tmp, which differs per user on macOS and under
     * php-fpm's PrivateTmp).
     */
    protected function withLock(callable $fn): mixed
    {
        if (! is_dir($this->lockPath) && ! @mkdir($this->lockPath, 0775, true) && ! is_dir($this->lockPath)) {
            throw new SystemException("Unable to create lock directory: {$this->lockPath}");
        }

        $path = $this->lockPath.'/links.lock';

        // flock() works on read-only handles, so a lock file created by another user still works
        $handle = @fopen($path, 'c') ?: @fopen($path, 'r');
        if ($handle === false) {
            throw new SystemException("Unable to open lock file: {$path}");
        }

        try {
            if (! flock($handle, LOCK_EX)) {
                throw new SystemException('Unable to acquire the lock for changing links.');
            }

            return $fn();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
