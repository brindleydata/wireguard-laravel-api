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

    public function findAvailableIp(string $interface_address, array $existing_peers): string
    {
        return $this->ipAllocator->findAvailableIp($interface_address, $existing_peers);
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

    public function createLink(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        if (str_contains($ip, '/')) {
            $this->validator->validateCidr($ip);
        } else {
            $this->validator->validateIpAddress($ip);
        }
        $this->validateSettings(['dns' => $dns, 'keepalive' => $keepalive, 'allowed_ips' => $allowed_ips, 'ifout' => $ifout]);

        return $this->withLock($name, function () use ($name, $ip, $port, $ifout, $dns, $keepalive, $allowed_ips, $forward, $nat, $up) {
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
            $address = str_contains($ip, '/') ? $ip : "{$ip}/24";

            $others = $this->otherLinks($name);
            $port = $port ?? $this->freePort($others);
            $this->validator->validatePort($port);
            $this->assertNoClash($port, $address, $others);
            $privkey = $this->keys->genkey();

            $content = $this->configBuilder->buildConfFile($address, $privkey, $port, $ifout, [], $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
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

    public function updateLink(string $name, array $params): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        // Validate provided fields
        if (isset($params['port'])) {
            $this->validator->validatePort((int) $params['port']);
        }
        if (isset($params['address'])) {
            if (str_contains($params['address'], '/')) {
                $this->validator->validateCidr($params['address']);
            } else {
                $this->validator->validateIpAddress($params['address']);
                $params['address'] .= '/24';
            }
        }
        $this->validateSettings($params);
        if (isset($params['ifout'])) {
            $system_interfaces = $this->os->networkInterfaces();
            if (! in_array($params['ifout'], $system_interfaces)) {
                throw new InvalidArgumentException("Output interface does not exist: {$params['ifout']}");
            }
        }

        return $this->withLock($name, function () use ($name, $params) {
            $meta = $this->os->parseConfig($name);
            if ($meta === null) {
                throw new NotFoundException("Link does not exist: {$name}");
            }

            if (isset($params['port']) || isset($params['address'])) {
                $this->assertNoClash(
                    isset($params['port']) ? (int) $params['port'] : null,
                    $params['address'] ?? null,
                    $this->otherLinks($name),
                );
            }
            if (isset($params['address'])) {
                $this->assertPeersFit($name, $params['address']);
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
            foreach (['dns', 'keepalive', 'allowed_ips', 'ifout', 'address'] as $field) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = (string) $params[$field];
                }
            }
            if (isset($params['port'])) {
                $overrides['port'] = (string) $params['port'];
            }
            foreach (['forward' => $forward, 'nat' => $nat, 'up' => $up] as $field => $value) {
                if (array_key_exists($field, $params)) {
                    $overrides[$field] = $value ? 'true' : 'false';
                }
            }

            // Address and port are applied by wg-quick, so a running link has to restart
            $restart = $running && $up && (isset($params['address']) || isset($params['port']));

            // Rewrite while the interface still exists: a running link's peers are read from it
            $this->rewriteConf($name, $iface, $overrides);

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

            $link = $this->getLink($name) ?? throw new NotFoundException("Link does not exist: {$name}");

            // Endpoint port and the link's client defaults are baked into every stored client config
            if (array_intersect(['port', 'dns', 'keepalive', 'allowed_ips'], array_keys($params)) !== []) {
                $current_meta = $this->os->parseConfig($name) ?? [];
                foreach ($link->peers as $peer) {
                    $this->refreshClientConfig($link, $peer->public_key, $meta, $current_meta);
                }
            }

            return $link;
        });
    }

    // ─── Peer operations ─────────────────────────────────────────────
    //
    // On a running link a change is applied with `wg` and the .conf is then regenerated from the
    // live interface. On a stopped link only the .conf is edited; wg-quick loads it on the next start.

    public function addPeer(string $link_name, ?string $ip = null): PeerInfo
    {
        return $this->withLock($link_name, function () use ($link_name, $ip) {
            $iface = $this->runtimeInterface($link_name);
            $link = $this->loadLink($link_name, $iface);
            if ($link === null) {
                throw new NotFoundException("Link does not exist: {$link_name}");
            }

            // Auto-assign IP if not provided
            $bare_ip = $ip === null || $ip === ''
                ? $this->ipAllocator->findAvailableIp($link->address, $link->peers)
                : $this->validator->peerAddress($ip);

            // Validate peer IP
            $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers);
            $this->validator->validateNewPeerIp($bare_ip, $link->address, $existing_ips);

            // Generate keys (base64)
            $privkey = $this->keys->genkey();
            $pubkey = $this->keys->pubkey($privkey);
            $psk = $this->keys->genpsk();

            $peer = [
                'public_key' => $pubkey,
                'preshared_key' => $psk,
                'allowed_ips' => "{$bare_ip}/32",
            ];

            if ($iface !== null) {
                // Piped through stdin so the preshared key never touches the disk
                $this->os->addPeer($iface, $this->peerSection($peer));
                $this->rewriteConf($link_name, $iface);
            } else {
                $this->rewriteConf($link_name, null, peers: fn (array $peers) => [...$peers, $peer]);
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

            if ($this->findPeer($link, $pubkey) === null) {
                throw new NotFoundException("Peer not found: {$pubkey}");
            }

            if ($iface !== null) {
                $this->os->removePeer($iface, $pubkey);
                $this->rewriteConf($link_name, $iface);
            } else {
                $this->rewriteConf($link_name, null, peers: fn (array $peers) => array_values(
                    array_filter($peers, fn (array $p) => $p['public_key'] !== $pubkey),
                ));
            }

            $this->os->deleteClientConfig($link_name, self::pubkeyToSafe($pubkey));
        });
    }

    public function getPeerConfig(string $link_name, string $pubkey): ?string
    {
        return $this->os->readClientConfig($link_name, self::pubkeyToSafe($pubkey));
    }

    /**
     * Change a peer.
     *
     * - `ip` moves its tunnel address: the server-side AllowedIPs and the client config's Address.
     * - `dns` and `allowed_ips` only change what its client config hands out (per-peer overrides of
     *   the link's client defaults), just like `allowed_ips` on a link.
     */
    public function updatePeer(string $link_name, string $pubkey, array $params): PeerInfo
    {
        $this->validateSettings($params);

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

            // Checked before changing anything: it holds the peer's private key
            $client_content = $this->os->readClientConfig($link_name, self::pubkeyToSafe($pubkey));
            if ($client_content === null) {
                throw new NotFoundException("Client config not found for peer: {$pubkey}");
            }

            $changes = array_intersect_key($params, array_flip(['dns', 'allowed_ips']));
            $allowed_ips = $target->allowed_ips;

            if (isset($params['ip'])) {
                $bare_ip = $this->validator->peerAddress($params['ip']);
                $others = array_filter($link->peers, fn (PeerInfo $p) => $p->public_key !== $pubkey);
                $this->validator->validateNewPeerIp($bare_ip, $link->address, array_map(fn (PeerInfo $p) => $p->allowed_ips, $others));

                $allowed_ips = "{$bare_ip}/32";
                $changes['ip'] = $bare_ip;

                if ($iface !== null) {
                    $this->os->setPeerAllowedIps($iface, $pubkey, $allowed_ips);
                    $this->rewriteConf($link_name, $iface);
                } else {
                    $this->rewriteConf($link_name, null, peers: fn (array $peers) => array_map(
                        fn (array $p) => $p['public_key'] === $pubkey ? array_merge($p, ['allowed_ips' => $allowed_ips]) : $p,
                        $peers,
                    ));
                }
            }

            $meta = $this->os->parseConfig($link_name) ?? [];
            $client_config = $this->refreshClientConfig($link, $pubkey, $meta, $meta, $changes, $client_content);
            $client = $this->configBuilder->parseClientConfig($client_config);

            return new PeerInfo(
                public_key: $pubkey,
                preshared_key: $client['PresharedKey'] ?? $target->preshared_key,
                allowed_ips: $allowed_ips,
                client_config: $client_config,
            );
        });
    }

    /**
     * Re-render a peer's stored client config for the link's current settings.
     *
     * A value that differs from the link default in force when the config was written
     * ($previous_meta) is a per-peer override and is kept. $changes (ip, dns, allowed_ips)
     * replace values. Returns null when the peer has no stored client config (added elsewhere).
     */
    protected function refreshClientConfig(InterfaceInfo $link, string $pubkey, array $previous_meta, array $current_meta, array $changes = [], ?string $content = null): ?string
    {
        $safe = self::pubkeyToSafe($pubkey);
        $content ??= $this->os->readClientConfig($link->name, $safe);
        if ($content === null) {
            return null;
        }

        $client = $this->configBuilder->parseClientConfig($content);
        $previous = $this->configBuilder->clientDefaults($previous_meta);
        $override = fn (string $field, string $key): ?string => array_key_exists($field, $changes)
            ? (string) $changes[$field]
            : (isset($client[$key]) && $client[$key] !== $previous[$field] ? $client[$key] : null);

        $config = $this->configBuilder->buildClientConfig(
            $link,
            $client['PrivateKey'],
            $changes['ip'] ?? $client['Address'],
            $pubkey,
            $client['PresharedKey'],
            dns_override: $override('dns', 'DNS'),
            allowed_ips_override: $override('allowed_ips', 'AllowedIPs'),
            metadata: $current_meta,
            keepalive_override: $override('keepalive', 'PersistentKeepalive'),
        );
        $this->os->writeClientConfig($link->name, $safe, $config);

        return $config;
    }

    /**
     * Validate the settings that get written into config files, when present.
     */
    protected function validateSettings(array $settings): void
    {
        if (isset($settings['dns'])) {
            $this->validator->validateDns((string) $settings['dns']);
        }
        if (isset($settings['allowed_ips'])) {
            $this->validator->validateAllowedIps((string) $settings['allowed_ips']);
        }
        if (isset($settings['keepalive'])) {
            $this->validator->validateKeepalive((int) $settings['keepalive']);
        }
        if (isset($settings['ifout'])) {
            $this->validator->validateOutboundInterface((string) $settings['ifout']);
        }
    }

    // ─── Backup and restore ──────────────────────────────────────────

    /**
     * Everything needed to recreate every link: its config (with all keys), whether it is running,
     * and the stored client configs of its peers.
     *
     * @return array<string, array{conf: string, up: bool, clients: array<string, string>}>
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
                    $safe = self::pubkeyToSafe($peer['PublicKey'] ?? '');
                    if (($client = $this->os->readClientConfig($name, $safe)) !== null) {
                        $clients[$safe] = $client;
                    }
                }

                return ['conf' => $conf, 'up' => $this->isRunning($name), 'clients' => $clients];
            });
            if ($link !== null) {
                $links[$name] = $link;
            }
        }

        return $links;
    }

    /**
     * Recreate a link from an exported config, for this server: the config is rebuilt by this
     * OS's driver (hooks, helper path), a missing outbound interface falls back to the default
     * route's, and client configs are re-rendered with this server's hostname (keeping per-peer
     * overrides).
     *
     * @param  array<string, string>  $clients  safe pubkey => client config
     * @return array{ifout: array{0: ?string, 1: string}|null, clients: int}
     */
    public function restoreLink(string $name, string $conf, array $clients, bool $up): array
    {
        $this->validator->validateInterfaceName($name);

        $parsed = $this->configBuilder->parseConfContent($conf);
        $meta = $parsed['metadata'];
        $address = $meta['address'] ?? $parsed['interface']['Address'] ?? '';
        $port = (int) ($parsed['interface']['ListenPort'] ?? 0);
        $this->validator->validateCidr($address);
        $this->validator->validatePort($port);
        $this->validateSettings(['dns' => $meta['dns'] ?? null, 'keepalive' => $meta['keepalive'] ?? null, 'allowed_ips' => $meta['allowed_ips'] ?? null]);

        return $this->withLock($name, function () use ($name, $parsed, $meta, $address, $port, $clients, $up) {
            if (in_array($name, $this->listLinks(), true)) {
                throw new ConflictException("Link already exists: {$name}");
            }
            $this->assertNoClash($port, $address, $this->otherLinks($name));

            $ifout = $meta['ifout'] ?? null;
            $moved = null;
            if ($ifout === null || ! in_array($ifout, $this->os->networkInterfaces(), true)) {
                $moved = [$ifout, $this->os->defaultOutboundInterface()];
                $ifout = $moved[1];
            }

            $peers = $this->confPeers($parsed['peers']);
            $this->os->writeConfig($name, $this->configBuilder->buildConfFile(
                address: $address,
                privkey: $parsed['interface']['PrivateKey'] ?? '',
                port: $port,
                ifout: $ifout,
                peers: $peers,
                dns: $meta['dns'] ?? null,
                keepalive: isset($meta['keepalive']) ? (int) $meta['keepalive'] : null,
                allowed_ips: $meta['allowed_ips'] ?? null,
                forward: ($meta['forward'] ?? 'false') === 'true',
                nat: ($meta['nat'] ?? 'false') === 'true',
                up: $up,
            ));

            $link = $this->getLinkFromConfig($name);
            $current_meta = $this->os->parseConfig($name) ?? [];
            $keys = array_column($peers, 'public_key');
            $restored = 0;
            foreach ($clients as $safe => $client) {
                $pubkey = self::safeToPubkey((string) $safe);
                if (in_array($pubkey, $keys, true) && $this->refreshClientConfig($link, $pubkey, $meta, $current_meta, [], $client) !== null) {
                    $restored++;
                }
            }

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
                    $this->os->deleteClientConfigDir($name);

                    throw new SystemException("Failed to start restored link {$name}: {$e->getMessage()}", 0, $e);
                }
            }

            return ['ifout' => $moved, 'clients' => $restored];
        });
    }

    /**
     * Why a link with this port and address can't live next to the existing ones (empty: it can).
     *
     * @param  list<string>  $ignore  links that won't be there (e.g. about to be replaced)
     * @return list<string>
     */
    public function findClashes(string $name, int $port, string $address, array $ignore = []): array
    {
        $problems = [];
        foreach ($this->otherLinks($name) as $other => $settings) {
            if (in_array($other, $ignore, true)) {
                continue;
            }
            if ($port === $settings['port']) {
                $problems[] = "port {$port} is used by {$other}";
            }
            if ($settings['address'] !== '' && IpAllocator::overlaps($address, $settings['address'])) {
                $problems[] = "subnet {$address} overlaps {$other} ({$settings['address']})";
            }
        }

        return $problems;
    }

    // ─── Runtime state ───────────────────────────────────────────────

    /**
     * The OS interface of a running link (utunN on macOS), or null when it is down.
     */
    protected function runtimeInterface(string $name): ?string
    {
        $iface = $this->os->resolveInterface($name);

        return in_array($iface, $this->runningInterfaces(), true) ? $iface : null;
    }

    protected function runningInterfaces(): array
    {
        return $this->os->runningInterfaces();
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

        $meta = $this->os->parseConfig($name) ?? [];

        return new InterfaceInfo(
            name: $name,
            public_key: $public_key,
            listen_port: (int) ($iface_parts[2] ?? 0),
            address: $this->os->interfaceAddress($iface) ?? $meta['address'] ?? '(none)',
            ifout: $meta['ifout'] ?? $this->os->defaultOutboundInterface(),
            forward: ($meta['forward'] ?? 'false') === 'true',
            nat: ($meta['nat'] ?? 'false') === 'true',
            up: true,
            peers: array_map(fn (array $p) => $this->peerInfo($p), $this->parseDumpPeers($lines)),
            interface: $iface,
        );
    }

    protected function getLinkFromConfig(string $name): ?InterfaceInfo
    {
        $content = $this->os->readConfig($name);
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
            address: $metadata['address'] ?? $interface['Address'] ?? '(none)',
            ifout: $metadata['ifout'] ?? $this->os->defaultOutboundInterface(),
            forward: ($metadata['forward'] ?? 'false') === 'true',
            nat: ($metadata['nat'] ?? 'false') === 'true',
            up: false,
            peers: array_map(fn (array $p) => $this->peerInfo($p), $this->confPeers($parsed['peers'])),
        );
    }

    // ─── Clash checks ────────────────────────────────────────────────

    /**
     * Listen port and address of every other link, from their configs.
     *
     * @return array<string, array{port: int, address: string}>
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
                'address' => $parsed['metadata']['address'] ?? $parsed['interface']['Address'] ?? '',
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
     * Two links can't listen on the same port or route overlapping subnets.
     */
    protected function assertNoClash(?int $port, ?string $address, array $others): void
    {
        foreach ($others as $other => $settings) {
            if ($port !== null && $port === $settings['port']) {
                throw new ConflictException("Port {$port} is already used by link {$other}");
            }
            if ($address !== null && $settings['address'] !== '' && IpAllocator::overlaps($address, $settings['address'])) {
                throw new ConflictException("Subnet {$address} overlaps link {$other} ({$settings['address']})");
            }
        }
    }

    /**
     * A link's address can only move to a subnet its peers' tunnel addresses still fit in.
     */
    protected function assertPeersFit(string $name, string $address): void
    {
        [$link_ip] = explode('/', $address, 2);

        foreach ($this->getLink($name)?->peers ?? [] as $peer) {
            // The first allowed IP is the peer's tunnel address
            $ip = explode('/', trim(explode(',', (string) $peer->allowed_ips)[0]), 2)[0];
            if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                continue;
            }
            if ($ip === $link_ip || ! $this->validator->ipInRange($ip, $address)) {
                throw new InvalidArgumentException("Peer {$ip} would not fit the new address {$address}. Move the peer first (its `ip`).");
            }
        }
    }

    // ─── Config regeneration ─────────────────────────────────────────

    /**
     * Regenerate a link's .conf from its current contents plus metadata overrides.
     *
     * Peers come from the live interface when $iface is given (the source of truth after
     * `wg addconf` / `wg set`), otherwise from the file itself. $peers can transform that list.
     */
    protected function rewriteConf(string $name, ?string $iface, array $overrides = [], ?Closure $peers = null): void
    {
        $content = $this->os->readConfig($name);
        if ($content === null) {
            return; // A running interface that no .conf manages
        }

        $parsed = $this->configBuilder->parseConfContent($content);
        $meta = array_merge($parsed['metadata'], $overrides);
        $interface = $parsed['interface'];

        $current = $iface !== null ? $this->dumpPeers($iface) : $this->confPeers($parsed['peers']);

        $this->os->writeConfig($name, $this->configBuilder->buildConfFile(
            address: $meta['address'] ?? $interface['Address'] ?? '',
            privkey: $interface['PrivateKey'] ?? '',
            port: isset($meta['port']) ? (int) $meta['port'] : (int) ($interface['ListenPort'] ?? 0),
            ifout: $meta['ifout'] ?? $this->os->defaultOutboundInterface(),
            peers: $peers !== null ? $peers($current) : $current,
            dns: $meta['dns'] ?? null,
            keepalive: isset($meta['keepalive']) ? (int) $meta['keepalive'] : null,
            allowed_ips: $meta['allowed_ips'] ?? null,
            forward: ($meta['forward'] ?? 'false') === 'true',
            nat: ($meta['nat'] ?? 'false') === 'true',
            up: ($meta['up'] ?? 'true') === 'true',
        ));
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
                'allowed_ips' => $parts[3],
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
            ];
            if (! empty($section['PresharedKey'])) {
                $peer['preshared_key'] = $section['PresharedKey'];
            }
            $peers[] = $peer;
        }

        return $peers;
    }

    protected function peerInfo(array $peer): PeerInfo
    {
        return new PeerInfo(
            public_key: $peer['public_key'],
            preshared_key: $peer['preshared_key'] ?? null,
            allowed_ips: $peer['allowed_ips'],
            endpoint: $peer['endpoint'] ?? null,
            latest_handshake: $peer['latest_handshake'] ?? null,
            transfer_rx: $peer['transfer_rx'] ?? null,
            transfer_tx: $peer['transfer_tx'] ?? null,
        );
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
        return implode("\n", [
            '[Peer]',
            "PublicKey = {$peer['public_key']}",
            "PresharedKey = {$peer['preshared_key']}",
            "AllowedIPs = {$peer['allowed_ips']}",
        ])."\n";
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
