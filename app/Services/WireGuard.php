<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\DTOs\PeerInfo;
use App\Exceptions\CommandFailedException;
use App\Exceptions\ConflictException;
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

    // ─── Key generation (delegates to KeyManager) ───────────────────

    public function genkey(): string
    {
        return $this->keys->genkey();
    }

    public function genpsk(): string
    {
        return $this->keys->genpsk();
    }

    public function pubkey(string $privkey): string
    {
        return $this->keys->pubkey($privkey);
    }

    public static function pubkeyToSafe(string $pubkey): string
    {
        return KeyManager::pubkeyToSafe($pubkey);
    }

    public static function safeToPubkey(string $safe): string
    {
        return KeyManager::safeToPubkey($safe);
    }

    // ─── IP allocation (delegates to IpAllocator) ───────────────────

    public function findAvailableIp(string $interface_address, array $existing_peers, ?string $address6 = null): string
    {
        return $this->ipAllocator->findAvailableIp($interface_address, $existing_peers, $address6);
    }

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

    public function getLink(string $name): ?InterfaceInfo
    {
        return $this->loadLink($name, $this->runtimeInterface($name));
    }

    /**
     * @param  string|null  $address6  IPv6 address and prefix for a dual-stack link, or 'auto' for a
     *                                 random unique local /64
     */
    public function createLink(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true, ?string $address6 = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        $address = $this->validator->linkAddress(str_contains($ip, '/') ? $ip : "{$ip}/24");
        $address6 = $this->resolveAddress6($address6, $address);
        ['dns' => $dns, 'allowed_ips' => $allowed_ips] = $this->validateSettings(['dns' => $dns, 'keepalive' => $keepalive, 'allowed_ips' => $allowed_ips, 'ifout' => $ifout]);

        return $this->withLock($name, function () use ($name, $address, $address6, $port, $ifout, $dns, $keepalive, $allowed_ips, $forward, $nat, $up) {
            if (in_array($name, $this->listLinks(), true)) {
                throw new ConflictException("Link already exists: {$name}");
            }

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
            $privkey = $this->keys->genkey();

            $content = $this->configBuilder->buildConfFile($address, $privkey, $port, $ifout, [], $dns, $keepalive, $allowed_ips, $forward, $nat, $up, $address6);
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
                    $this->os->deleteConfig($name);

                    throw new SystemException("Failed to create link {$name}: {$e->getMessage()}", 0, $e);
                }
            }

            return $this->getLink($name) ?? throw new SystemException("Link {$name} was created but could not be read back.");
        });
    }

    public function deleteLink(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $this->withLock($name, function () use ($name) {
            $iface = $this->runtimeInterface($name);

            if ($iface === null && ! $this->os->configExists($name)) {
                throw new NotFoundException("Link does not exist: {$name}");
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

            $this->os->deleteConfig($name);
            $this->os->deleteClientConfigDir($name);
        });
    }

    /**
     * Change a link's settings. `dns`, `keepalive` and `allowed_ips` are the link's own client
     * defaults: null (or '') removes one, so the global WIREGUARD_* default applies again.
     *
     * A change that needs the link (re)started is undone when the link then doesn't start: the
     * previous config goes back and a link that was running runs again.
     *
     * A new `address` in another subnet needs `move_peers`: each peer then keeps its host number
     * there (10.0.0.5 → 10.1.0.5), and every client needs its new config.
     */
    public function updateLink(string $name, array $params): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

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

        return $this->withLock($name, function () use ($name, $params) {
            $content = $this->os->readConfig($name);
            if ($content === null) {
                throw new NotFoundException("Link does not exist: {$name}");
            }
            $this->assertManaged($name, $content);
            $meta = ConfigBuilder::parseMetadata($content);
            if (isset($params['address']) && ! str_contains($params['address'], '/')) {
                $params['address'] = $this->validator->linkAddress($params['address'].'/'.(explode('/', $meta['address'] ?? '', 2)[1] ?? '24'));
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

            $forward = array_key_exists('forward', $params) ? (bool) $params['forward'] : $current_forward;
            $nat = array_key_exists('nat', $params) ? (bool) $params['nat'] : $current_nat;
            $ifout = $params['ifout'] ?? $current_ifout;
            $up = array_key_exists('up', $params) ? (bool) $params['up'] : $running;

            // Metadata overrides, only for fields that were provided
            $overrides = [];
            foreach (['ifout', 'address'] as $field) {
                if (isset($params[$field])) {
                    $overrides[$field] = (string) $params[$field];
                }
            }
            // The link's client defaults: null takes one out, back to the global default
            foreach (['dns', 'keepalive', 'allowed_ips'] as $field) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = $params[$field] === null ? null : (string) $params[$field];
                }
            }
            if (isset($params['port'])) {
                $overrides['port'] = (string) $params['port'];
            }
            $overrides['address6'] = $address6;
            foreach (['forward' => $forward, 'nat' => $nat, 'up' => $up] as $field => $value) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = $value ? 'true' : 'false';
                }
            }

            // Addresses and port are applied by wg-quick, so a running link has to restart
            $readdress = isset($params['address']) || $changed6;
            $restart = $running && $up && ($readdress || isset($params['port']));

            // Rewrite while the interface still exists: a running link's peers are read from it.
            // Peers' IPv6 addresses mirror their IPv4 host number, so they move with the addresses.
            $this->rewriteConf($name, $iface, $overrides, $readdress && ($address6 !== null || $current6 !== null || $moved_from !== null)
                ? fn (array $peers) => $this->readdressPeers($peers, $address, $address6, $current6, $moved_from)
                : null, $content);

            try {
                if ($running && (! $up || $restart)) {
                    $this->os->stopInterface($name);
                    $this->os->clearFirewall($name);
                }

                if ($up && (! $running || $restart)) {
                    // PostUp installs the rules for the new state
                    $this->os->startInterface($name);
                } elseif ($running && $up && ($forward !== $current_forward || $nat !== $current_nat || $ifout !== $current_ifout)) {
                    // The rules come from the config rewritten above
                    $this->os->applyFirewall($name, $iface);
                }
            } catch (\Throwable $e) {
                throw $this->revert($name, $content, $running, $e);
            }

            $link = $this->getLink($name) ?? throw new NotFoundException("Link does not exist: {$name}");

            // Endpoint port, addresses and the link's client defaults are baked into every stored client config
            if ($changed6 || array_intersect(['port', 'dns', 'keepalive', 'allowed_ips', 'address'], array_keys($params)) !== []) {
                $current_meta = $this->os->parseConfig($name) ?? [];
                foreach ($link->peers as $peer) {
                    $this->refreshClientConfig($link, $peer->public_key, $peer->allowed_ips, $peer->clientSettings(), $current_meta);
                }
            }

            return $link;
        });
    }

    // ─── Peer operations ─────────────────────────────────────────────
    //
    // On a running link a change is applied with `wg` and the .conf is then regenerated from the
    // live interface. On a stopped link only the .conf is edited; wg-quick loads it on the next start.

    /**
     * Add a peer: the next free address unless $ip is given, an optional label, and optional
     * networks behind it (site-to-site), which wg-quick routes to it.
     */
    public function addPeer(string $link_name, ?string $ip = null, ?string $name = null, ?string $networks = null): PeerInfo
    {
        $name = $name === null || $name === '' ? null : $this->validator->peerName($name);
        $networks = $networks === null || $networks === '' ? [] : $this->validator->networks($networks);

        return $this->withLock($link_name, function () use ($link_name, $ip, $name, $networks) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw new NotFoundException("Link does not exist: {$link_name}");
            }
            $conf = $this->managedConf($link_name);

            // Auto-assign IP if not provided
            $bare_ip = $ip === null || $ip === ''
                ? $this->ipAllocator->findAvailableIp($link->address, $link->peers, $link->address6)
                : $this->validator->peerAddress($ip);

            // Validate peer IP
            $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers);
            $this->validator->validateNewPeerIp($bare_ip, $link->address, $existing_ips, $link->address6);
            $this->assertNetworksFree($link, $networks);

            // Generate keys (base64)
            $privkey = $this->keys->genkey();
            $pubkey = $this->keys->pubkey($privkey);
            $psk = $this->keys->genpsk();

            $peer = [
                'public_key' => $pubkey,
                'preshared_key' => $psk,
                'allowed_ips' => implode(', ', [IpAllocator::peerAllowedIps($bare_ip, $link->address, $link->address6), ...$networks]),
                'name' => $name,
            ];

            if ($iface !== null && $networks === []) {
                // On stdin: the preshared key is never on a command line (the helper keeps it in a
                // private temp file only while it checks it)
                $this->os->addPeer($iface, $this->peerSection($peer));
            }
            $this->rewriteConf($link_name, $iface, peers: fn (array $peers) => $this->putPeer($peers, $peer), content: $conf);
            if ($iface !== null && $networks !== []) {
                // wg-quick routes the networks when the link starts
                $this->restartOrRevert($link_name, $conf);
            }

            $client_config = $this->configBuilder->buildClientConfig($link, $privkey, $bare_ip, $pubkey, $psk);

            // Save client config keyed by base64url-safe pubkey
            $this->os->writeClientConfig($link_name, self::pubkeyToSafe($pubkey), $client_config);

            return new PeerInfo(
                public_key: $pubkey,
                preshared_key: $psk,
                allowed_ips: $peer['allowed_ips'],
                private_key: $privkey,
                client_config: $client_config,
                name: $name,
                networks: $networks === [] ? null : implode(', ', $networks),
            );
        });
    }

    public function removePeer(string $link_name, string $pubkey): void
    {
        $this->withLock($link_name, function () use ($link_name, $pubkey) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw new NotFoundException("Link does not exist: {$link_name}");
            }

            $target = $this->findPeer($link, $pubkey);
            if ($target === null) {
                throw new NotFoundException("Peer not found: {$pubkey}");
            }
            $conf = $this->managedConf($link_name);

            // wg-quick routed the networks behind it when the link started, and only a restart
            // takes those routes away again (as when updatePeer() changes them)
            $reroute = $iface !== null && $target->enabled && $target->networks !== null;
            // A disabled peer isn't on the interface
            if ($iface !== null && $target->enabled && ! $reroute) {
                $this->os->removePeer($iface, $pubkey);
            }
            $this->rewriteConf($link_name, $iface, peers: fn (array $peers) => array_values(
                array_filter($peers, fn (array $p) => $p['public_key'] !== $pubkey),
            ), content: $conf);
            if ($reroute) {
                $this->restartOrRevert($link_name, $conf);
            }

            $this->os->deleteClientConfig($link_name, self::pubkeyToSafe($pubkey));
        });
    }

    /**
     * A peer's stored client config, or null when there is none. Takes the public key in either
     * form (base64 or URL-safe); a malformed key or link name has no config.
     */
    public function getPeerConfig(string $link_name, string $pubkey): ?string
    {
        $pubkey = self::safeToPubkey(self::pubkeyToSafe($pubkey));
        if (! $this->isLinkName($link_name) || ! KeyManager::isKey($pubkey)) {
            return null;
        }

        return $this->os->readClientConfig($link_name, self::pubkeyToSafe($pubkey));
    }

    /**
     * Change a peer.
     *
     * - `ip` moves its tunnel address: the server-side AllowedIPs and the client config's Address.
     * - `dns`, `allowed_ips` and `keepalive` only change what its client config hands out: the
     *   peer's own values instead of the link's client defaults, just like `allowed_ips` on a
     *   link. They are stored with the peer in the link config. null (or '') takes one out: the
     *   peer follows its link again.
     * - `name` labels it (null or '' removes the label).
     * - `enabled` false takes it off the interface but keeps its keys, address and client config.
     * - `networks` are routed to it (site-to-site; null or '' removes them). wg-quick sets up the
     *   routes, so a change to the routed networks restarts a running link. If the link doesn't
     *   start with them, the change is undone.
     */
    public function updatePeer(string $link_name, string $pubkey, array $params): PeerInfo
    {
        $params = $this->validateSettings($params);
        if (array_key_exists('name', $params)) {
            $params['name'] = $params['name'] === null || $params['name'] === '' ? null : $this->validator->peerName((string) $params['name']);
        }
        if (array_key_exists('networks', $params)) {
            $params['networks'] = $params['networks'] === null || $params['networks'] === '' ? [] : $this->validator->networks((string) $params['networks']);
        }

        return $this->withLock($link_name, function () use ($link_name, $pubkey, $params) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw new NotFoundException("Link does not exist: {$link_name}");
            }

            $target = $this->findPeer($link, $pubkey);
            if ($target === null) {
                throw new NotFoundException("Peer not found: {$pubkey}");
            }

            $conf = $this->managedConf($link_name);

            // Checked before changing anything: it holds the peer's private key
            $client_content = $this->os->readClientConfig($link_name, self::pubkeyToSafe($pubkey));
            if ($client_content === null) {
                throw new NotFoundException("Client config not found for peer: {$pubkey}");
            }

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
            ];
            // Its own client settings, where given (param => peer field): null takes one out
            foreach (['dns' => 'dns', 'keepalive' => 'keepalive', 'allowed_ips' => 'client_allowed_ips'] as $param => $field) {
                if (array_key_exists($param, $params)) {
                    $peer[$field] = $params[$param] === null ? null : (string) $params[$param];
                }
            }

            // Live changes, unless the routed networks change: then the link restarts with the config
            $reroute = $iface !== null && ($target->enabled ? $old_networks : []) != ($enabled ? $networks : []);
            $live = $iface !== null && ! $reroute;
            if ($live && ! $target->enabled && $enabled) {
                $this->os->addPeer($iface, $this->peerSection($peer));
            } elseif ($live && $target->enabled && $enabled && $allowed_ips !== $target->allowed_ips) {
                $this->os->setPeerAllowedIps($iface, $pubkey, $allowed_ips);
            }
            $saved = $this->rewriteConf($link_name, $iface, peers: fn (array $peers) => $this->putPeer($peers, $peer), content: $conf);
            if ($live && $target->enabled && ! $enabled) {
                // Off the interface only now: the config is rewritten from the live peers, and a
                // peer that isn't among them any more would lose its place and what is saved with it
                $this->os->removePeer($iface, $pubkey);
            }
            if ($reroute) {
                $this->restartOrRevert($link_name, $conf);
            }

            // The peer as it is saved now (a running interface without a config saves nothing)
            $stored = array_find($saved, fn (array $p) => $p['public_key'] === $pubkey)
                ?? [...['dns' => $target->dns, 'keepalive' => $target->keepalive, 'client_allowed_ips' => $target->client_allowed_ips], ...$peer];
            $updated = $this->peerInfo($stored, $link->address6);

            // A peer change leaves the link's metadata as it is
            $client_config = $this->refreshClientConfig($link, $pubkey, $allowed_ips, $updated->clientSettings(), ConfigBuilder::parseMetadata($conf ?? ''), $client_content);

            return new PeerInfo(
                public_key: $pubkey,
                preshared_key: $this->configBuilder->parseClientConfig($client_config)['PresharedKey'] ?? $target->preshared_key,
                allowed_ips: $allowed_ips,
                client_config: $client_config,
                name: $peer['name'],
                enabled: $enabled,
                networks: $networks === [] ? null : implode(', ', $networks),
                dns: $updated->dns,
                keepalive: $updated->keepalive,
                client_allowed_ips: $updated->client_allowed_ips,
            );
        });
    }

    /**
     * Re-render a peer's stored client config. Only its keys come from the stored one: its tunnel
     * address is the one in the link config ($allowed_ips), and everything else is the link's
     * settings ($meta) unless the peer has its own ($own: dns, keepalive, allowed_ips).
     * Returns null when the peer has no stored client config (added elsewhere).
     *
     * @param  array{dns?: ?string, keepalive?: int|string|null, allowed_ips?: ?string}  $own
     */
    protected function refreshClientConfig(InterfaceInfo $link, string $pubkey, ?string $allowed_ips, array $own, array $meta, ?string $content = null): ?string
    {
        $safe = self::pubkeyToSafe($pubkey);
        $content ??= $this->os->readClientConfig($link->name, $safe);
        if ($content === null) {
            return null;
        }

        $client = $this->configBuilder->parseClientConfig($content);
        $config = $this->configBuilder->buildClientConfig(
            $link,
            $client['PrivateKey'],
            IpAllocator::tunnelIp($allowed_ips) ?? $client['Address'],
            $pubkey,
            $client['PresharedKey'],
            dns_override: $own['dns'] ?? null,
            allowed_ips_override: $own['allowed_ips'] ?? null,
            metadata: $meta,
            keepalive_override: isset($own['keepalive']) ? (string) $own['keepalive'] : null,
        );
        $this->os->writeClientConfig($link->name, $safe, $config);

        return $config;
    }

    /**
     * Peers of a config from before a peer's own client settings were stored with it (format 1).
     * Back then they only showed in its client config: whatever that has and its link doesn't
     * hand out was the peer's own, so it is recorded as such. Once: the config is then written
     * in the current format, and nothing is ever inferred again.
     *
     * @param  array  $meta  the link's metadata the client configs were written with
     * @param  callable(string): ?string  $client  a peer's stored client config, by public key
     */
    protected function adoptClientSettings(array $meta, array $peers, callable $client): array
    {
        $defaults = $this->configBuilder->clientDefaults($meta);
        $same = fn (string $a, string $b) => str_replace(' ', '', $a) === str_replace(' ', '', $b);

        foreach ($peers as $i => $peer) {
            if (! KeyManager::isKey($peer['public_key']) || ($content = $client($peer['public_key'])) === null) {
                continue;
            }

            $stored = $this->configBuilder->parseClientConfig($content);
            foreach (['dns' => 'DNS', 'keepalive' => 'PersistentKeepalive', 'allowed_ips' => 'AllowedIPs'] as $setting => $key) {
                $field = $setting === 'allowed_ips' ? 'client_allowed_ips' : $setting;
                if (isset($peer[$field]) || ! isset($stored[$key]) || $same($stored[$key], $defaults[$setting])) {
                    continue;
                }
                try {
                    $peers[$i][$field] = (string) $this->validateSettings([$setting => $stored[$key]])[$setting];
                } catch (InvalidArgumentException) {
                    // Not a value the app would have written: the peer follows its link
                }
            }
        }

        return $peers;
    }

    /**
     * Validate the settings that get written into config files, when present. Returns them as
     * they are written: lists as `a, b`, and an empty dns, keepalive or allowed_ips as null
     * ("the default").
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
            $link = $this->withLock($name, function () use ($name) {
                $conf = $this->os->readConfig($name);
                if ($conf === null) {
                    return null;
                }

                $clients = [];
                foreach ($this->configBuilder->parseConfContent($conf)['peers'] as $peer) {
                    if (! KeyManager::isKey($peer['PublicKey'] ?? '')) {
                        continue;
                    }
                    $safe = self::pubkeyToSafe($peer['PublicKey']);
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
        if (! in_array($name, $this->listLinks(), true) && in_array($name, $this->os->networkInterfaces(), true)) {
            $problems[] = "A network interface named {$name} already exists";
        }
        $others = array_diff_key($this->otherLinks($name), array_flip($ignore));

        return [...$problems, ...$this->clashes($plan['port'], $plan['address'], $others, $plan['address6'], $plan['networks'])];
    }

    /**
     * Recreate a link from an exported config, for this server: the config is rebuilt by this
     * OS's driver (hooks, helper path), a missing outbound interface falls back to the default
     * route's, and client configs are re-rendered with this server's hostname (keeping per-peer
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
    public function restoreLink(string $name, string $conf, array $clients, bool $up, bool $replace = false): array
    {
        $plan = $this->restorePlan($name, $conf);

        return $this->withLock($name, function () use ($name, $plan, $clients, $up, $replace) {
            ['meta' => $meta, 'address' => $address, 'address6' => $address6, 'peers' => $peers] = $plan;
            $clients = array_filter($clients, 'is_string');
            // A backup from before peers' own client settings were stored with them
            if ((int) ($meta['format'] ?? 1) < ConfigBuilder::FORMAT) {
                $peers = $this->adoptClientSettings($meta, $peers, fn (string $pubkey) => $clients[self::pubkeyToSafe($pubkey)] ?? null);
            }

            $exists = in_array($name, $this->listLinks(), true);
            if ($exists && ! $replace) {
                throw new ConflictException("Link already exists: {$name}");
            }
            $system_interfaces = $this->os->networkInterfaces();
            if (! $exists && in_array($name, $system_interfaces, true)) {
                throw new ConflictException("A network interface named {$name} already exists");
            }
            $this->assertNoClash($plan['port'], $address, $this->otherLinks($name), $address6, $plan['networks']);

            $ifout = $meta['ifout'] ?? null;
            $moved = null;
            if ($ifout === null || ! in_array($ifout, $system_interfaces, true)) {
                $moved = [$ifout, $this->os->defaultOutboundInterface()];
                $ifout = $moved[1];
            }

            $content = $this->buildConf($plan['interface'], array_merge($meta, [
                'address' => $address,
                'address6' => $address6,
                'port' => $plan['port'],
                'ifout' => $ifout,
                'up' => $up ? 'true' : 'false',
            ]), $peers);

            // A link being replaced is untouched so far, and stays so if the helper refuses the
            // new config: that is checked before it takes the old one's place
            $old = $exists ? $this->os->readConfig($name) : null;
            $was_running = $exists && $this->runtimeInterface($name) !== null;
            $this->os->writeConfig($name, $content);

            if ($exists) {
                try {
                    $this->os->stopInterface($name);
                } catch (\Throwable $e) {
                    // Only a running link must stop (as in deleteLink). It still runs: its own config again
                    if ($was_running) {
                        if ($old !== null) {
                            $this->os->writeConfig($name, $old);
                        }

                        throw $e;
                    }
                }
                $this->os->clearFirewall($name);
                $this->os->deleteClientConfigDir($name);
            }

            // Client configs: the backup's keys, rendered for this server
            $link = $this->getLinkFromConfig($name);
            $current_meta = ConfigBuilder::parseMetadata($content);
            $restored = 0;
            foreach ($link->peers as $peer) {
                $client = KeyManager::isKey($peer->public_key) ? ($clients[self::pubkeyToSafe($peer->public_key)] ?? null) : null;
                if ($client !== null && $this->refreshClientConfig($link, $peer->public_key, $peer->allowed_ips, $peer->clientSettings(), $current_meta, $client) !== null) {
                    $restored++;
                }
            }

            $start_error = null;
            if ($up) {
                try {
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

            return ['ifout' => $moved, 'clients' => $restored, 'start_error' => $start_error];
        });
    }

    /**
     * A backed-up config, checked and taken apart for restoreLink(). Throws when it can't be
     * restored: an invalid name, address, port or setting, or lines the app doesn't write.
     *
     * @return array{interface: array, meta: array, address: string, address6: ?string, port: int, peers: list<array>, networks: list<string>}
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
        $this->validateSettings(['dns' => $meta['dns'] ?? null, 'keepalive' => $meta['keepalive'] ?? null, 'allowed_ips' => $meta['allowed_ips'] ?? null]);

        $peers = $this->confPeers($parsed['peers']);
        // Networks behind its peers need routes too, which no other link may have
        $networks = array_merge([], ...array_map(fn (array $peer) => IpAllocator::networksOf($peer['allowed_ips'], $address6), $peers));

        return ['interface' => $parsed['interface'], 'meta' => $meta, 'address' => $address, 'address6' => $address6, 'port' => $port, 'peers' => $peers, 'networks' => $networks];
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
        } catch (CommandFailedException) {
            return null; // Stopped since it was listed
        }
        if ($output === '') {
            return null;
        }

        $lines = explode("\n", $output);

        // Line 1: private_key, public_key, listen_port, fwmark (tab-separated)
        $iface_parts = explode("\t", $lines[0]);
        $private_key = $iface_parts[0] ?? '';
        $public_key = $private_key !== '' && $private_key !== '(none)' ? $this->keys->pubkey($private_key) : '';

        // Names and disabled peers only live in the config
        $parsed = $this->configBuilder->parseConfContent($this->os->readConfig($name) ?? '');
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
        );
    }

    protected function getLinkFromConfig(string $name): ?InterfaceInfo
    {
        $content = $this->isLinkName($name) ? $this->os->readConfig($name) : null;
        if ($content === null) {
            return null;
        }

        $parsed = $this->configBuilder->parseConfContent($content);
        $metadata = $parsed['metadata'];
        $interface = $parsed['interface'];

        $private_key = $interface['PrivateKey'] ?? '';

        return new InterfaceInfo(
            name: $name,
            public_key: $private_key !== '' ? $this->keys->pubkey($private_key) : '',
            listen_port: (int) ($interface['ListenPort'] ?? 0),
            address: $metadata['address'] ?? trim(explode(',', $interface['Address'] ?? '(none)')[0]),
            ifout: $metadata['ifout'] ?? $this->os->defaultOutboundInterface(),
            forward: ($metadata['forward'] ?? 'false') === 'true',
            nat: ($metadata['nat'] ?? 'false') === 'true',
            up: false,
            peers: array_map(fn (array $p) => $this->peerInfo($p, $metadata['address6'] ?? null), $this->confPeers($parsed['peers'])),
            address6: $metadata['address6'] ?? null,
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
                foreach (array_filter([$address, $address6]) as $own) {
                    if (IpAllocator::overlaps($own, $network)) {
                        $problems[] = "{$own} overlaps {$network}, routed to a peer of link {$other}";
                    }
                }
            }
            foreach ($networks as $network) {
                foreach (array_filter([$settings['address'], $settings['address6'], ...$routed]) as $entry) {
                    if (IpAllocator::overlaps($network, $entry)) {
                        $problems[] = "{$network} overlaps {$entry} of link {$other}";
                    }
                }
            }
        }

        return $problems;
    }

    protected function assertNoClash(?int $port, ?string $address, array $others, ?string $address6 = null, array $networks = []): void
    {
        if (($problems = $this->clashes($port, $address, $others, $address6, $networks)) !== []) {
            throw new ConflictException($problems[0]);
        }
    }

    /**
     * Networks behind a peer can't overlap the link's own addresses, another peer's addresses or
     * networks, or another link's subnets and peers: each route can only lead to one peer.
     *
     * @param  list<string>  $networks
     * @param  string|null  $pubkey  the peer they're for, when it exists already
     */
    protected function assertNetworksFree(InterfaceInfo $link, array $networks, ?string $pubkey = null): void
    {
        foreach ($networks as $network) {
            foreach (array_filter([$link->address, $link->address6]) as $own) {
                if (IpAllocator::overlaps($network, $own)) {
                    throw new InvalidArgumentException("{$network} overlaps the link's own addresses ({$own}).");
                }
            }
            foreach ($link->peers as $peer) {
                foreach ($peer->public_key === $pubkey ? [] : array_map('trim', explode(',', (string) $peer->allowed_ips)) as $entry) {
                    if ($entry !== '' && IpAllocator::overlaps($network, $entry)) {
                        throw new ConflictException("{$network} overlaps {$entry} of peer ".($peer->name ?? $peer->public_key));
                    }
                }
            }
            foreach ($this->otherLinks($link->name) as $other => $settings) {
                foreach (array_filter([$settings['address'], $settings['address6'], ...$settings['peers']]) as $entry) {
                    if (IpAllocator::overlaps($network, $entry)) {
                        throw new ConflictException("{$network} overlaps {$entry} of link {$other}");
                    }
                }
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
    protected function restartOrRevert(string $name, ?string $conf): void
    {
        try {
            $this->restart($name);
        } catch (\Throwable $e) {
            // A running interface that no .conf manages has nothing to go back to
            throw $conf === null ? $e : $this->revert($name, $conf, true, $e);
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
            return new SystemException("The change to link {$name} could not be applied, and undoing it failed too (check the link with wg:link {$name}): {$e->getMessage()}", 0, $e);
        }

        return new SystemException("The change to link {$name} could not be applied and was undone: {$e->getMessage()}", 0, $e);
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

        foreach ($this->getLink($name)?->peers ?? [] as $peer) {
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
                foreach (array_filter([$address, $address6]) as $own) {
                    if (IpAllocator::overlaps($network_behind, $own)) {
                        throw new InvalidArgumentException("{$own} would overlap {$network_behind}, routed to peer {$ip}.");
                    }
                }
            }
        }
    }

    // ─── Config regeneration ─────────────────────────────────────────

    /**
     * Regenerate a link's .conf from its current contents plus metadata overrides.
     *
     * Peers come from the live interface when $iface is given (the source of truth after
     * `wg addconf` / `wg set`), otherwise from the file itself. $peers can transform that list.
     * $content is the config, when the caller has read it already.
     *
     * @return list<array> the peers as they were written (empty: no .conf)
     */
    protected function rewriteConf(string $name, ?string $iface, array $overrides = [], ?Closure $peers = null, ?string $content = null): array
    {
        $content ??= $this->os->readConfig($name);
        if ($content === null) {
            return []; // A running interface that no .conf manages
        }

        $parsed = $this->configBuilder->parseConfContent($content);
        $saved = $this->confPeers($parsed['peers']);
        // An older config: what its peers have of their own is still only in their client configs
        if ((int) ($parsed['metadata']['format'] ?? 1) < ConfigBuilder::FORMAT) {
            $saved = $this->adoptClientSettings($parsed['metadata'], $saved, fn (string $pubkey) => $this->os->readClientConfig($name, self::pubkeyToSafe($pubkey)));
        }
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
            up: ($meta['up'] ?? 'true') === 'true',
            address6: $meta['address6'] ?? null,
        );
    }

    /**
     * A link's config before a change to it (null: a running interface that no .conf manages).
     * Refuses a config the app can't change without losing something: see assertManaged().
     */
    protected function managedConf(string $name): ?string
    {
        $content = $this->os->readConfig($name);
        if ($content !== null) {
            $this->assertManaged($name, $content);
        }

        return $content;
    }

    /**
     * The .conf is always regenerated whole, so a hand-written one would lose whatever the app
     * doesn't write: MTU, Table, hooks of its own, a peer's Endpoint, comments. Such a config
     * can be read and deleted, but not changed.
     */
    protected function assertManaged(string $name, string $content): void
    {
        $what = $this->unmanagedSettings($content);
        if ($what === []) {
            return;
        }

        $shown = implode(', ', array_slice($what, 0, 6)).(count($what) > 6 ? ', …' : '');

        throw new ConflictException("Link {$name} has settings this app doesn't manage ({$shown}), and a change made here would drop them. Edit its config by hand, or take them out first.");
    }

    /**
     * What a config has that regenerating it would drop, named by key only (a line may hold a
     * secret): e.g. ['MTU', 'Endpoint', 'comments']. Empty for a config the app can manage.
     *
     * @return list<string>
     */
    protected function unmanagedSettings(string $content): array
    {
        $parsed = $this->configBuilder->parseConfContent($content);
        // Any outbound interface will do here: this is about what a rewrite would leave out
        $rebuilt = $this->buildConf($parsed['interface'], $parsed['metadata'] + ['ifout' => 'none'], $this->confPeers($parsed['peers']));

        $what = [];
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

    protected function peerInfo(array $peer, ?string $address6): PeerInfo
    {
        $networks = IpAllocator::networksOf($peer['allowed_ips'], $address6);

        return new PeerInfo(
            public_key: $peer['public_key'],
            preshared_key: $peer['preshared_key'] ?? null,
            allowed_ips: $peer['allowed_ips'],
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
        );
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
                $peers[] = [...$live[$peer['public_key']], ...array_intersect_key($peer, ConfigBuilder::PEER_SETTINGS), 'enabled' => true];
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
        ]))."\n";
    }

    // ─── Locking ─────────────────────────────────────────────────────

    /**
     * Serialize changes to one link across processes. The lock directory is shared by the CLI and
     * the web server (unlike /tmp, which differs per user on macOS and under php-fpm's PrivateTmp).
     */
    protected function withLock(string $name, callable $fn): mixed
    {
        if (! is_dir($this->lockPath) && ! @mkdir($this->lockPath, 0775, true) && ! is_dir($this->lockPath)) {
            throw new SystemException("Unable to create lock directory: {$this->lockPath}");
        }

        $path = $this->lockPath.'/'.preg_replace('/[^A-Za-z0-9_.=+-]/', '_', $name).'.lock';

        // flock() works on read-only handles, so a lock file created by another user still works
        $handle = @fopen($path, 'c') ?: @fopen($path, 'r');
        if ($handle === false) {
            throw new SystemException("Unable to open lock file: {$path}");
        }

        try {
            if (! flock($handle, LOCK_EX)) {
                throw new SystemException("Unable to acquire lock for link: {$name}");
            }

            return $fn();
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }
}
