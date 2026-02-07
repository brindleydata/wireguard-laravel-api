<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\DTOs\PeerInfo;
use App\DTOs\SystemStatus;
use App\Services\Os\OsDriver;
use App\Validation\WireGuardValidator;
use RuntimeException;

class WireGuard
{
    public function __construct(
        protected array $config,
        protected OsDriver $os,
        protected WireGuardValidator $validator,
        protected WireGuardSocket $socket,
        protected InterfaceMap $interface_map,
        protected string $storage_path,
    ) {}

    // ─── Key generation (pure PHP, no shell) ─────────────────────────

    public function genkey(): string
    {
        $key = random_bytes(32);

        // X25519 clamping
        $key[0] = chr(ord($key[0]) & 248);
        $key[31] = chr((ord($key[31]) & 127) | 64);

        return base64_encode($key);
    }

    public function genpsk(): string
    {
        return base64_encode(random_bytes(32));
    }

    public function pubkey(string $privkey): string
    {
        return base64_encode(sodium_crypto_scalarmult_base(base64_decode($privkey)));
    }

    // ─── System status ───────────────────────────────────────────────

    public function systemStatus(): SystemStatus
    {
        $ip_service = $this->config['ip_service'] ?? 'http://ifconfig.me/ip';
        $endpoint = $this->os->publicIp($ip_service);

        return new SystemStatus(
            app: [
                'name' => config('app.name'),
                'version' => config('app.version', '0.0'),
            ],
            cpu: $this->os->cpu(),
            ram: $this->os->ram(),
            disk: $this->os->disk(),
            endpoint: $endpoint,
        );
    }

    // ─── Interface operations ────────────────────────────────────────

    public function listInterfaces(): array
    {
        $os_names = $this->socket->listInterfaces();
        $names = [];

        foreach ($os_names as $os_name) {
            $friendly = $this->interface_map->friendlyName($os_name);
            $names[] = $friendly ?? $os_name;
        }

        return $names;
    }

    public function getInterface(string $name): ?InterfaceInfo
    {
        $os_name = $this->interface_map->resolve($name);

        if (! $this->socket->socketExists($os_name)) {
            return null;
        }

        $data = $this->socket->get($os_name);

        // Convert hex keys to base64
        $private_key = $data['private_key'] ? WireGuardSocket::hexToBase64($data['private_key']) : '';
        $public_key = $private_key !== '' ? $this->pubkey($private_key) : '';
        $listen_port = $data['listen_port'];

        // Get address from OS or JSON config
        $address = $this->os->interfaceAddress($os_name);
        if ($address === null) {
            $config = $this->readConfig($name);
            $address = $config['address'] ?? '(none)';
        }

        // Get ifout from JSON config
        $config = $this->readConfig($name);
        $ifout = $config['ifout'] ?? $this->os->defaultOutboundInterface();

        // Build peer list
        $peers = [];
        foreach ($data['peers'] as $peer_data) {
            $peer_pub_key = WireGuardSocket::hexToBase64($peer_data['public_key']);
            $peer_psk = $peer_data['preshared_key'] !== null
                ? WireGuardSocket::hexToBase64($peer_data['preshared_key'])
                : null;
            $allowed_ips = implode(', ', $peer_data['allowed_ips']);

            $peers[] = new PeerInfo(
                public_key: $peer_pub_key,
                preshared_key: $peer_psk,
                allowed_ips: $allowed_ips,
            );
        }

        return new InterfaceInfo(
            name: $name,
            public_key: $public_key,
            private_key: $private_key,
            listen_port: $listen_port,
            address: $address,
            ifout: $ifout,
            peers: $peers,
        );
    }

    public function createInterface(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        $this->validator->validateIpAddress($ip);

        if ($this->socket->socketExists($this->interface_map->resolve($name))) {
            throw new RuntimeException("Interface already exists: {$name}");
        }

        if (file_exists($this->storagePath($name.'.json'))) {
            throw new RuntimeException("Interface already exists: {$name}");
        }

        // Check that ifout exists (if specified)
        if ($ifout !== null) {
            $system_interfaces = $this->os->networkInterfaces();
            if (! in_array($ifout, $system_interfaces)) {
                throw new RuntimeException("Output interface does not exist: {$ifout}");
            }
        }

        $ifout = $ifout ?? $this->os->defaultOutboundInterface();
        $port = $port ?? mt_rand(33000, 65000);
        $this->validator->validatePort($port);

        $address = str_contains($ip, '/') ? $ip : "{$ip}/24";
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);

        // Save forwarding state before enabling (on first interface)
        $is_first = count($this->interface_map->all()) === 0;
        if ($is_first) {
            $this->saveForwardingState();
        }

        // Enable IP forwarding
        $this->os->enableForwarding();

        // Create the OS-level network device
        $os_name = $this->os->createInterface($name);

        // Register the mapping
        $this->interface_map->register($name, $os_name);

        try {
            // Wait for socket to appear
            $this->waitForSocket($os_name);

            // Configure via UAPI
            $privkey_hex = WireGuardSocket::base64ToHex($privkey);
            $this->socket->set($os_name, [
                'private_key' => $privkey_hex,
                'listen_port' => $port,
            ]);

            // Assign IP address
            $this->os->assignAddress($os_name, $address);

            // Bring interface up
            $this->os->bringUp($os_name);

            // Add NAT rules
            $this->os->addNatRules($os_name, $address, $ifout);
        } catch (\Throwable $e) {
            // Rollback: remove NAT, destroy device, unregister mapping
            $this->os->removeNatRules($os_name);
            try {
                $this->os->destroyInterface($os_name);
            } catch (\Throwable) {
            }
            $this->interface_map->unregister($name);

            if ($is_first) {
                $this->restoreForwardingState();
            }

            throw new RuntimeException("Failed to create interface {$name}: {$e->getMessage()}", 0, $e);
        }

        // Write JSON config (only include per-interface overrides when set)
        $config_data = [
            'private_key' => $privkey_hex,
            'listen_port' => $port,
            'address' => $address,
            'ifout' => $ifout,
            'peers' => [],
        ];
        if ($dns !== null) {
            $config_data['dns'] = $dns;
        }
        if ($keepalive !== null) {
            $config_data['keepalive'] = $keepalive;
        }
        if ($allowed_ips !== null) {
            $config_data['allowed_ips'] = $allowed_ips;
        }
        $this->writeConfig($name, $config_data);

        return new InterfaceInfo(
            name: $name,
            public_key: $pubkey,
            private_key: $privkey,
            listen_port: $port,
            address: $address,
            ifout: $ifout,
        );
    }

    public function deleteInterface(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $os_name = $this->interface_map->resolve($name);

        if (! $this->socket->socketExists($os_name) && ! file_exists($this->storagePath($name.'.json'))) {
            throw new RuntimeException("Interface does not exist: {$name}");
        }

        $this->os->removeNatRules($os_name);

        try {
            $this->os->destroyInterface($os_name);
        } catch (\Throwable) {
        }

        $this->interface_map->unregister($name);

        $config_file = $this->storagePath($name.'.json');
        if (file_exists($config_file)) {
            @unlink($config_file);
        }

        $client_dir = $this->storagePath("clients/{$name}");
        if (is_dir($client_dir)) {
            $files = glob("{$client_dir}/*");
            foreach ($files as $file) {
                @unlink($file);
            }
            @rmdir($client_dir);
        }

        if (count($this->interface_map->all()) === 0) {
            $this->restoreForwardingState();
        }
    }

    // ─── Lifecycle (startup / shutdown) ─────────────────────────────

    /**
     * Get names of all interfaces that have a JSON config (persisted desired state).
     */
    public function configuredInterfaces(): array
    {
        $pattern = $this->storagePath('*.json');
        $files = glob($pattern);

        if ($files === false || $files === []) {
            return [];
        }

        return array_map(
            fn (string $path) => basename($path, '.json'),
            $files,
        );
    }

    /**
     * Restore all persisted interfaces from JSON configs.
     * Returns [name => true/false] indicating success per interface.
     */
    public function startupAll(): array
    {
        $results = [];
        $names = $this->configuredInterfaces();

        if ($names === []) {
            return $results;
        }

        if (count($this->interface_map->all()) === 0) {
            $this->saveForwardingState();
        }
        $this->os->enableForwarding();

        foreach ($names as $name) {
            try {
                $this->restoreInterface($name);
                $results[$name] = true;
            } catch (\Throwable $e) {
                $results[$name] = false;
            }
        }

        return $results;
    }

    /**
     * Gracefully tear down all running interfaces. JSON configs are preserved.
     * Returns [name => true/false] indicating success per interface.
     */
    public function shutdownAll(): array
    {
        $results = [];

        foreach ($this->interface_map->all() as $name => $os_name) {
            try {
                $this->os->removeNatRules($os_name);

                try {
                    $this->os->destroyInterface($os_name);
                } catch (\Throwable) {
                }

                $this->interface_map->unregister($name);
                $results[$name] = true;
            } catch (\Throwable) {
                $results[$name] = false;
            }
        }

        if (count($this->interface_map->all()) === 0) {
            $this->restoreForwardingState();
        }

        return $results;
    }

    /**
     * Restore a single interface from its JSON config.
     */
    protected function restoreInterface(string $name): void
    {
        $config = $this->readConfig($name);
        if ($config === []) {
            throw new RuntimeException("No config found for interface: {$name}");
        }

        $private_key_hex = $config['private_key'];
        $listen_port = $config['listen_port'];
        $address = $config['address'];
        $ifout = $config['ifout'] ?? $this->os->defaultOutboundInterface();

        $os_name = $this->os->createInterface($name);
        $this->interface_map->register($name, $os_name);

        try {
            $this->waitForSocket($os_name);

            $this->socket->set($os_name, [
                'private_key' => $private_key_hex,
                'listen_port' => $listen_port,
            ]);

            // Restore peers
            $peers = $config['peers'] ?? [];
            if ($peers !== []) {
                $uapi_peers = [];
                foreach ($peers as $peer) {
                    $uapi_peer = [
                        'public_key' => $peer['public_key'],
                        'replace_allowed_ips' => true,
                        'allowed_ips' => (array) $peer['allowed_ips'],
                    ];
                    if (! empty($peer['preshared_key'])) {
                        $uapi_peer['preshared_key'] = $peer['preshared_key'];
                    }
                    $uapi_peers[] = $uapi_peer;
                }
                $this->socket->set($os_name, [], $uapi_peers);
            }

            $this->os->assignAddress($os_name, $address);
            $this->os->bringUp($os_name);
            $this->os->addNatRules($os_name, $address, $ifout);
        } catch (\Throwable $e) {
            $this->os->removeNatRules($os_name);
            try {
                $this->os->destroyInterface($os_name);
            } catch (\Throwable) {
            }
            $this->interface_map->unregister($name);

            throw new RuntimeException("Failed to restore interface {$name}: {$e->getMessage()}", 0, $e);
        }
    }

    // ─── Peer operations ─────────────────────────────────────────────

    public function addPeer(string $interface_name, string $ip): PeerInfo
    {
        $interface = $this->getInterface($interface_name);
        if ($interface === null) {
            throw new RuntimeException("Interface does not exist: {$interface_name}");
        }

        // Validate peer IP
        $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $interface->peers);
        $this->validator->validateNewPeerIp($ip, $interface->address, $existing_ips);

        // Generate keys
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);
        $psk = $this->genpsk();

        $os_name = $this->interface_map->resolve($interface_name);
        $allowed_ips = "{$ip}/32";

        // Set peer via UAPI — keys sent as hex over socket, no temp files needed
        $pubkey_hex = WireGuardSocket::base64ToHex($pubkey);
        $psk_hex = WireGuardSocket::base64ToHex($psk);

        $this->socket->set($os_name, [], [
            [
                'public_key' => $pubkey_hex,
                'preshared_key' => $psk_hex,
                'replace_allowed_ips' => true,
                'allowed_ips' => [$allowed_ips],
            ],
        ]);

        // Build client config
        $client_config = $this->buildClientConfig($interface, $privkey, $ip, $pubkey, $psk);

        // Save client config file
        $this->saveClientConfig($interface_name, $ip, $client_config);

        // Update JSON config with new peer
        $this->addPeerToConfig($interface_name, [
            'public_key' => $pubkey_hex,
            'preshared_key' => $psk_hex,
            'allowed_ips' => $allowed_ips,
        ]);

        return new PeerInfo(
            public_key: $pubkey,
            preshared_key: $psk,
            allowed_ips: $allowed_ips,
            private_key: $privkey,
            client_config: $client_config,
        );
    }

    public function removePeer(string $interface_name, string $peer_identifier): void
    {
        $interface = $this->getInterface($interface_name);
        if ($interface === null) {
            throw new RuntimeException("Interface does not exist: {$interface_name}");
        }

        $target_pubkey = null;
        $target_ip = null;
        foreach ($interface->peers as $peer) {
            $peer_ip_clean = str_replace('/32', '', $peer->allowed_ips);
            if ($peer->public_key === $peer_identifier || $peer_ip_clean === $peer_identifier) {
                $target_pubkey = $peer->public_key;
                $target_ip = $peer_ip_clean;
                break;
            }
        }

        if ($target_pubkey === null) {
            throw new RuntimeException("Peer not found: {$peer_identifier}");
        }

        $os_name = $this->interface_map->resolve($interface_name);
        $pubkey_hex = WireGuardSocket::base64ToHex($target_pubkey);

        $this->socket->set($os_name, [], [
            [
                'public_key' => $pubkey_hex,
                'remove' => true,
            ],
        ]);

        $this->removePeerFromConfig($interface_name, $pubkey_hex);

        if ($target_ip !== null) {
            $client_file = $this->storagePath("clients/{$interface_name}/{$target_ip}.conf");
            if (file_exists($client_file)) {
                @unlink($client_file);
            }
        }
    }

    public function getPeerConfig(string $interface_name, string $ip): ?string
    {
        $client_file = $this->storagePath("clients/{$interface_name}/{$ip}.conf");

        if (! file_exists($client_file)) {
            return null;
        }

        return file_get_contents($client_file);
    }

    // ─── Private helpers ─────────────────────────────────────────────

    protected function storagePath(string $path = ''): string
    {
        $base = rtrim($this->storage_path, '/');

        return $path !== '' ? "{$base}/{$path}" : $base;
    }

    protected function waitForSocket(string $os_name, int $max_wait_ms = 3000): void
    {
        $waited = 0;
        $interval = 100_000; // 100ms in microseconds

        while (! $this->socket->socketExists($os_name) && $waited < $max_wait_ms) {
            usleep($interval);
            $waited += 100;
        }

        if (! $this->socket->socketExists($os_name)) {
            throw new RuntimeException("Socket for {$os_name} did not appear within {$max_wait_ms}ms");
        }
    }

    protected function readConfig(string $name): array
    {
        $file = $this->storagePath($name.'.json');
        if (! file_exists($file)) {
            return [];
        }

        $content = file_get_contents($file);
        $decoded = json_decode($content, true);

        return is_array($decoded) ? $decoded : [];
    }

    protected function writeConfig(string $name, array $data): void
    {
        $dir = $this->storagePath();
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $file = $this->storagePath($name.'.json');
        file_put_contents(
            $file,
            json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
        );
    }

    protected function addPeerToConfig(string $name, array $peer): void
    {
        $config = $this->readConfig($name);
        $config['peers'] = $config['peers'] ?? [];
        $config['peers'][] = $peer;
        $this->writeConfig($name, $config);
    }

    protected function removePeerFromConfig(string $name, string $pubkey_hex): void
    {
        $config = $this->readConfig($name);
        $config['peers'] = array_values(array_filter(
            $config['peers'] ?? [],
            fn (array $p) => ($p['public_key'] ?? '') !== $pubkey_hex,
        ));
        $this->writeConfig($name, $config);
    }

    protected function saveForwardingState(): void
    {
        $state_file = $this->storagePath('.forwarding-state');
        $dir = dirname($state_file);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $enabled = $this->os->isForwardingEnabled();
        file_put_contents($state_file, $enabled ? '1' : '0');
    }

    protected function restoreForwardingState(): void
    {
        $state_file = $this->storagePath('.forwarding-state');
        if (! file_exists($state_file)) {
            return;
        }

        $was_enabled = trim(file_get_contents($state_file)) === '1';
        if (! $was_enabled) {
            $this->os->disableForwarding();
        }

        @unlink($state_file);
    }

    protected function buildClientConfig(InterfaceInfo $interface, string $privkey, string $ip, string $pubkey, string $psk): string
    {
        // Per-interface overrides from JSON config, falling back to global defaults
        $if_config = $this->readConfig($interface->name);
        $dns = $if_config['dns'] ?? $this->config['default_dns'] ?? '8.8.8.8';
        $keepalive = $if_config['keepalive'] ?? $this->config['default_keepalive'] ?? 25;
        $allowed_ips = $if_config['allowed_ips'] ?? $this->config['allowed_ips'] ?? '0.0.0.0/0';
        $endpoint_ip = $this->config['endpoint_ip'] ?? null;

        if ($endpoint_ip === null) {
            $ip_service = $this->config['ip_service'] ?? 'http://ifconfig.me/ip';
            $endpoint_ip = $this->os->publicIp($ip_service);
        }

        $endpoint = "{$endpoint_ip}:{$interface->listen_port}";

        $template = $this->config['templates']['client'] ?? null;
        if ($template !== null) {
            return str_replace(
                ['{privkey}', '{pubkey}', '{psk}', '{subnets}', '{keepalive}', '{dns}', '{endpoint}', '{ip}'],
                [$privkey, $interface->public_key, $psk, $allowed_ips, $keepalive, $dns, $endpoint, $ip],
                $template,
            );
        }

        return implode("\n", [
            '[Interface]',
            "PrivateKey = {$privkey}",
            "Address = {$ip}/32",
            "DNS = {$dns}",
            '',
            '[Peer]',
            "PublicKey = {$interface->public_key}",
            "PresharedKey = {$psk}",
            "AllowedIPs = {$allowed_ips}",
            "Endpoint = {$endpoint}",
            "PersistentKeepalive = {$keepalive}",
        ]);
    }

    protected function saveClientConfig(string $interface_name, string $ip, string $config): void
    {
        $client_dir = $this->storagePath("clients/{$interface_name}");
        if (! is_dir($client_dir)) {
            mkdir($client_dir, 0755, true);
        }

        $client_file = "{$client_dir}/{$ip}.conf";
        file_put_contents($client_file, $config."\n");
    }
}
