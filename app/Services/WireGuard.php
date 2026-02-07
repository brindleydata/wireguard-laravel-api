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
        protected Shell $shell,
        protected OsDriver $os,
        protected WireGuardValidator $validator,
        protected WireGuardSocket $socket,
        protected InterfaceMap $interfaceMap,
        protected string $storagePath,
    ) {}

    // ─── Key generation ──────────────────────────────────────────────

    public function genkey(): string
    {
        return $this->shell->exec(['wg', 'genkey']);
    }

    public function genpsk(): string
    {
        return $this->shell->exec(['wg', 'genpsk']);
    }

    public function pubkey(string $privkey): string
    {
        return $this->shell->exec(['wg', 'pubkey'], input: $privkey);
    }

    // ─── System status ───────────────────────────────────────────────

    public function systemStatus(): SystemStatus
    {
        $ipService = $this->config['ip_service'] ?? 'http://ifconfig.me/ip';
        $endpoint = $this->os->publicIp($ipService);

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
        $osNames = $this->socket->listInterfaces();
        $names = [];

        foreach ($osNames as $osName) {
            $friendly = $this->interfaceMap->friendlyName($osName);
            $names[] = $friendly ?? $osName;
        }

        return $names;
    }

    public function getInterface(string $name): ?InterfaceInfo
    {
        $osName = $this->interfaceMap->resolve($name);

        if (! $this->socket->socketExists($osName)) {
            return null;
        }

        $data = $this->socket->get($osName);

        // Convert hex keys to base64
        $privateKey = $data['private_key'] ? WireGuardSocket::hexToBase64($data['private_key']) : '';
        $publicKey = $privateKey !== '' ? $this->pubkey($privateKey) : '';
        $listenPort = $data['listen_port'];

        // Get address from OS or JSON config
        $address = $this->os->interfaceAddress($osName);
        if ($address === null) {
            $config = $this->readConfig($name);
            $address = $config['address'] ?? '(none)';
        }

        // Get ifout from JSON config
        $config = $this->readConfig($name);
        $ifout = $config['ifout'] ?? $this->os->defaultOutboundInterface();

        // Build peer list
        $peers = [];
        foreach ($data['peers'] as $peerData) {
            $peerPubKey = WireGuardSocket::hexToBase64($peerData['public_key']);
            $peerPsk = $peerData['preshared_key'] !== null
                ? WireGuardSocket::hexToBase64($peerData['preshared_key'])
                : null;
            $allowedIps = implode(', ', $peerData['allowed_ips']);

            $peers[] = new PeerInfo(
                publicKey: $peerPubKey,
                presharedKey: $peerPsk,
                allowedIps: $allowedIps,
            );
        }

        return new InterfaceInfo(
            name: $name,
            publicKey: $publicKey,
            privateKey: $privateKey,
            listenPort: $listenPort,
            address: $address,
            ifout: $ifout,
            peers: $peers,
        );
    }

    public function createInterface(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowedIps = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        $this->validator->validateIpAddress($ip);

        if ($this->socket->socketExists($this->interfaceMap->resolve($name))) {
            throw new RuntimeException("Interface already exists: {$name}");
        }

        // Check JSON config too
        if (file_exists($this->storagePath($name.'.json'))) {
            throw new RuntimeException("Interface already exists: {$name}");
        }

        // Check that ifout exists (if specified)
        if ($ifout !== null) {
            $systemInterfaces = $this->os->networkInterfaces();
            if (! in_array($ifout, $systemInterfaces)) {
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
        $isFirstInterface = count($this->interfaceMap->all()) === 0;
        if ($isFirstInterface) {
            $this->saveForwardingState();
        }

        // Enable IP forwarding
        $this->os->enableForwarding();

        // Create the OS-level network device
        $osName = $this->os->createInterface($name);

        // Register the mapping
        $this->interfaceMap->register($name, $osName);

        try {
            // Wait for socket to appear
            $this->waitForSocket($osName);

            // Configure via UAPI
            $privkeyHex = WireGuardSocket::base64ToHex($privkey);
            $this->socket->set($osName, [
                'private_key' => $privkeyHex,
                'listen_port' => $port,
            ]);

            // Assign IP address
            $this->os->assignAddress($osName, $address);

            // Bring interface up
            $this->os->bringUp($osName);

            // Add NAT rules
            $this->os->addNatRules($osName, $address, $ifout);
        } catch (\Throwable $e) {
            // Rollback: remove NAT, destroy device, unregister mapping
            $this->os->removeNatRules($osName);
            try {
                $this->os->destroyInterface($osName);
            } catch (\Throwable) {
            }
            $this->interfaceMap->unregister($name);

            if ($isFirstInterface) {
                $this->restoreForwardingState();
            }

            throw new RuntimeException("Failed to create interface {$name}: {$e->getMessage()}", 0, $e);
        }

        // Write JSON config (only include per-interface overrides when set)
        $configData = [
            'private_key' => $privkeyHex,
            'listen_port' => $port,
            'address' => $address,
            'ifout' => $ifout,
            'peers' => [],
        ];
        if ($dns !== null) {
            $configData['dns'] = $dns;
        }
        if ($keepalive !== null) {
            $configData['keepalive'] = $keepalive;
        }
        if ($allowedIps !== null) {
            $configData['allowed_ips'] = $allowedIps;
        }
        $this->writeConfig($name, $configData);

        return new InterfaceInfo(
            name: $name,
            publicKey: $pubkey,
            privateKey: $privkey,
            listenPort: $port,
            address: $address,
            ifout: $ifout,
        );
    }

    public function deleteInterface(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $osName = $this->interfaceMap->resolve($name);

        if (! $this->socket->socketExists($osName) && ! file_exists($this->storagePath($name.'.json'))) {
            throw new RuntimeException("Interface does not exist: {$name}");
        }

        // Remove NAT rules
        $this->os->removeNatRules($osName);

        // Destroy the device
        try {
            $this->os->destroyInterface($osName);
        } catch (\Throwable) {
            // Device may already be gone
        }

        // Unregister mapping
        $this->interfaceMap->unregister($name);

        // Remove JSON config
        $configFile = $this->storagePath($name.'.json');
        if (file_exists($configFile)) {
            @unlink($configFile);
        }

        // Remove client configs
        $clientDir = $this->storagePath("clients/{$name}");
        if (is_dir($clientDir)) {
            $files = glob("{$clientDir}/*");
            foreach ($files as $file) {
                @unlink($file);
            }
            @rmdir($clientDir);
        }

        // If this was the last interface, restore forwarding state
        if (count($this->interfaceMap->all()) === 0) {
            $this->restoreForwardingState();
        }
    }

    // ─── Peer operations ─────────────────────────────────────────────

    public function addPeer(string $interfaceName, string $ip): PeerInfo
    {
        $interface = $this->getInterface($interfaceName);
        if ($interface === null) {
            throw new RuntimeException("Interface does not exist: {$interfaceName}");
        }

        // Validate peer IP
        $existingIps = array_map(fn (PeerInfo $p) => $p->allowedIps, $interface->peers);
        $this->validator->validateNewPeerIp($ip, $interface->address, $existingIps);

        // Generate keys
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);
        $psk = $this->genpsk();

        $osName = $this->interfaceMap->resolve($interfaceName);
        $allowedIps = "{$ip}/32";

        // Set peer via UAPI — keys sent as hex over socket, no temp files needed
        $pubkeyHex = WireGuardSocket::base64ToHex($pubkey);
        $pskHex = WireGuardSocket::base64ToHex($psk);

        $this->socket->set($osName, [], [
            [
                'public_key' => $pubkeyHex,
                'preshared_key' => $pskHex,
                'replace_allowed_ips' => true,
                'allowed_ips' => [$allowedIps],
            ],
        ]);

        // Build client config
        $clientConfig = $this->buildClientConfig($interface, $privkey, $ip, $pubkey, $psk);

        // Save client config file
        $this->saveClientConfig($interfaceName, $ip, $clientConfig);

        // Update JSON config with new peer
        $this->addPeerToConfig($interfaceName, [
            'public_key' => $pubkeyHex,
            'preshared_key' => $pskHex,
            'allowed_ips' => $allowedIps,
        ]);

        return new PeerInfo(
            publicKey: $pubkey,
            presharedKey: $psk,
            allowedIps: $allowedIps,
            privateKey: $privkey,
            clientConfig: $clientConfig,
        );
    }

    public function removePeer(string $interfaceName, string $peerIdentifier): void
    {
        $interface = $this->getInterface($interfaceName);
        if ($interface === null) {
            throw new RuntimeException("Interface does not exist: {$interfaceName}");
        }

        // Find peer by public key or IP
        $targetPubkey = null;
        $targetIp = null;
        foreach ($interface->peers as $peer) {
            $peerIpClean = str_replace('/32', '', $peer->allowedIps);
            if ($peer->publicKey === $peerIdentifier || $peerIpClean === $peerIdentifier) {
                $targetPubkey = $peer->publicKey;
                $targetIp = $peerIpClean;
                break;
            }
        }

        if ($targetPubkey === null) {
            throw new RuntimeException("Peer not found: {$peerIdentifier}");
        }

        $osName = $this->interfaceMap->resolve($interfaceName);
        $pubkeyHex = WireGuardSocket::base64ToHex($targetPubkey);

        // Remove peer via UAPI
        $this->socket->set($osName, [], [
            [
                'public_key' => $pubkeyHex,
                'remove' => true,
            ],
        ]);

        // Remove from JSON config
        $this->removePeerFromConfig($interfaceName, $pubkeyHex);

        // Remove client config if it exists
        if ($targetIp !== null) {
            $clientFile = $this->storagePath("clients/{$interfaceName}/{$targetIp}.conf");
            if (file_exists($clientFile)) {
                @unlink($clientFile);
            }
        }
    }

    public function getPeerConfig(string $interfaceName, string $ip): ?string
    {
        $clientFile = $this->storagePath("clients/{$interfaceName}/{$ip}.conf");

        if (! file_exists($clientFile)) {
            return null;
        }

        return file_get_contents($clientFile);
    }

    // ─── Private helpers ─────────────────────────────────────────────

    protected function storagePath(string $path = ''): string
    {
        $base = rtrim($this->storagePath, '/');

        return $path !== '' ? "{$base}/{$path}" : $base;
    }

    protected function waitForSocket(string $osName, int $maxWaitMs = 3000): void
    {
        $waited = 0;
        $interval = 100_000; // 100ms in microseconds

        while (! $this->socket->socketExists($osName) && $waited < $maxWaitMs) {
            usleep($interval);
            $waited += 100;
        }

        if (! $this->socket->socketExists($osName)) {
            throw new RuntimeException("Socket for {$osName} did not appear within {$maxWaitMs}ms");
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

    protected function removePeerFromConfig(string $name, string $pubkeyHex): void
    {
        $config = $this->readConfig($name);
        $config['peers'] = array_values(array_filter(
            $config['peers'] ?? [],
            fn (array $p) => ($p['public_key'] ?? '') !== $pubkeyHex,
        ));
        $this->writeConfig($name, $config);
    }

    protected function saveForwardingState(): void
    {
        $stateFile = $this->storagePath('.forwarding-state');
        $dir = dirname($stateFile);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $enabled = $this->os->isForwardingEnabled();
        file_put_contents($stateFile, $enabled ? '1' : '0');
    }

    protected function restoreForwardingState(): void
    {
        $stateFile = $this->storagePath('.forwarding-state');
        if (! file_exists($stateFile)) {
            return;
        }

        $wasEnabled = trim(file_get_contents($stateFile)) === '1';
        if (! $wasEnabled) {
            $this->os->disableForwarding();
        }

        @unlink($stateFile);
    }

    protected function buildClientConfig(InterfaceInfo $interface, string $privkey, string $ip, string $pubkey, string $psk): string
    {
        // Per-interface overrides from JSON config, falling back to global defaults
        $ifConfig = $this->readConfig($interface->name);
        $dns = $ifConfig['dns'] ?? $this->config['default_dns'] ?? '8.8.8.8';
        $keepalive = $ifConfig['keepalive'] ?? $this->config['default_keepalive'] ?? 25;
        $allowedIps = $ifConfig['allowed_ips'] ?? $this->config['allowed_ips'] ?? '0.0.0.0/0';
        $endpointIp = $this->config['endpoint_ip'] ?? null;

        if ($endpointIp === null) {
            $ipService = $this->config['ip_service'] ?? 'http://ifconfig.me/ip';
            $endpointIp = $this->os->publicIp($ipService);
        }

        $endpoint = "{$endpointIp}:{$interface->listenPort}";

        $template = $this->config['templates']['client'] ?? null;
        if ($template !== null) {
            return str_replace(
                ['{privkey}', '{pubkey}', '{psk}', '{subnets}', '{keepalive}', '{dns}', '{endpoint}', '{ip}'],
                [$privkey, $interface->publicKey, $psk, $allowedIps, $keepalive, $dns, $endpoint, $ip],
                $template,
            );
        }

        // Fallback: build manually
        return implode("\n", [
            '[Interface]',
            "PrivateKey = {$privkey}",
            "Address = {$ip}/32",
            "DNS = {$dns}",
            '',
            '[Peer]',
            "PublicKey = {$interface->publicKey}",
            "PresharedKey = {$psk}",
            "AllowedIPs = {$allowedIps}",
            "Endpoint = {$endpoint}",
            "PersistentKeepalive = {$keepalive}",
        ]);
    }

    protected function saveClientConfig(string $interfaceName, string $ip, string $config): void
    {
        $clientDir = $this->storagePath("clients/{$interfaceName}");
        if (! is_dir($clientDir)) {
            mkdir($clientDir, 0755, true);
        }

        $clientFile = "{$clientDir}/{$ip}.conf";
        file_put_contents($clientFile, $config."\n");
    }
}
