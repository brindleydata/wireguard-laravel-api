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
        $output = $this->shell->tryExec(['wg', 'show', 'interfaces']);
        if ($output === null || $output === '') {
            return [];
        }

        return array_values(array_filter(
            preg_split('/\s+/', $output),
            fn ($s) => $s !== ''
        ));
    }

    public function getInterface(string $name): ?InterfaceInfo
    {
        if (! in_array($name, $this->listInterfaces())) {
            return null;
        }

        $escaped = escapeshellarg($name);

        // Get interface dump: privkey\tpubkey\tport\tfwmark
        $dump = $this->shell->run("sudo wg show {$escaped} dump");
        $lines = explode("\n", $dump);
        $ifaceLine = $lines[0] ?? '';
        $parts = explode("\t", $ifaceLine);
        $privateKey = $parts[0] ?? '';
        $publicKey = $parts[1] ?? '';
        $listenPort = (int) ($parts[2] ?? 0);

        // Get VPN address
        $address = $this->os->interfaceAddress($name) ?? '(none)';

        // Determine ifout from config file or default
        $ifout = $this->readIfoutFromConfig($name) ?? 'eth0';

        // Get peers
        $peers = $this->listPeers($name);

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

    public function createInterface(string $name, string $ip, ?int $port = null, ?string $ifout = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        $this->validator->validateIpAddress($ip);

        if (in_array($name, $this->listInterfaces())) {
            throw new RuntimeException("Interface already exists: {$name}");
        }

        // Check that ifout exists (if specified)
        if ($ifout !== null) {
            $systemInterfaces = $this->os->networkInterfaces();
            if (! in_array($ifout, $systemInterfaces)) {
                throw new RuntimeException("Output interface does not exist: {$ifout}");
            }
        }

        $ifout = $ifout ?? 'eth0';
        $port = $port ?? mt_rand(33000, 65000);
        $this->validator->validatePort($port);

        $address = str_contains($ip, '/') ? $ip : "{$ip}/24";
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);

        $configContent = $this->os->interfaceTemplate($address, $privkey, $port, $ifout);
        $configPath = $this->os->configPath();
        $configFile = "{$configPath}/{$name}.conf";

        // Write config file securely (no shell echo injection)
        $dir = dirname($configFile);
        if (! is_dir($dir)) {
            $this->shell->run('sudo mkdir -p '.escapeshellarg($dir));
        }

        // Write to temp file then move (avoids needing shell for file content)
        $tmpFile = tempnam(sys_get_temp_dir(), 'wg_');
        file_put_contents($tmpFile, $configContent."\n\n");
        $this->shell->run('sudo cp '.escapeshellarg($tmpFile).' '.escapeshellarg($configFile));
        $this->shell->run('sudo chmod 600 '.escapeshellarg($configFile));
        @unlink($tmpFile);

        // Start the interface
        $this->os->startInterface($name);

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

        if (! in_array($name, $this->listInterfaces())) {
            throw new RuntimeException("Interface does not exist: {$name}");
        }

        $this->os->stopInterface($name);

        $configPath = $this->os->configPath();
        $configFile = "{$configPath}/{$name}.conf";
        if (file_exists($configFile)) {
            $this->shell->run('sudo rm '.escapeshellarg($configFile));
        }

        // Remove client configs
        $clientDir = "{$configPath}/clients/{$name}";
        if (is_dir($clientDir)) {
            $this->shell->run('sudo rm -rf '.escapeshellarg($clientDir));
        }
    }

    // ─── Peer operations ─────────────────────────────────────────────

    public function listPeers(string $name): array
    {
        $escaped = escapeshellarg($name);
        $peers = [];

        // Get allowed-ips
        $allowedIps = $this->shell->tryRun("sudo wg show {$escaped} allowed-ips");
        if ($allowedIps !== null && $allowedIps !== '') {
            foreach (explode("\n", $allowedIps) as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                $parts = preg_split('/\s+/', $line, 2);
                $pubkey = $parts[0];
                $ip = $parts[1] ?? '';
                $peers[$pubkey] = ['ip' => $ip, 'psk' => null];
            }
        }

        // Get preshared-keys
        $psks = $this->shell->tryRun("sudo wg show {$escaped} preshared-keys");
        if ($psks !== null && $psks !== '') {
            foreach (explode("\n", $psks) as $line) {
                $line = trim($line);
                if ($line === '') {
                    continue;
                }
                $parts = preg_split('/\s+/', $line, 2);
                $pubkey = $parts[0];
                $psk = $parts[1] ?? '';
                if (isset($peers[$pubkey])) {
                    $peers[$pubkey]['psk'] = $psk !== '(none)' ? $psk : null;
                }
            }
        }

        return array_map(
            fn ($pubkey, $data) => new PeerInfo(
                publicKey: $pubkey,
                presharedKey: $data['psk'],
                allowedIps: $data['ip'],
            ),
            array_keys($peers),
            array_values($peers),
        );
    }

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

        $escapedInterface = escapeshellarg($interfaceName);
        $escapedPubkey = escapeshellarg($pubkey);
        $allowedIps = "{$ip}/32";
        $escapedIps = escapeshellarg($allowedIps);

        // Pass PSK via temp file to avoid /proc/cmdline exposure
        $pskFile = tempnam(sys_get_temp_dir(), 'wg_psk_');
        file_put_contents($pskFile, $psk);

        try {
            $this->shell->run(
                "sudo wg set {$escapedInterface} peer {$escapedPubkey} preshared-key ".escapeshellarg($pskFile)." allowed-ips {$escapedIps}"
            );
        } finally {
            @unlink($pskFile);
        }

        // Build client config
        $clientConfig = $this->buildClientConfig($interface, $privkey, $ip, $pubkey, $psk);

        // Save client config file
        $this->saveClientConfig($interfaceName, $ip, $clientConfig);

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

        $escapedInterface = escapeshellarg($interfaceName);
        $escapedPubkey = escapeshellarg($targetPubkey);
        $this->shell->run("sudo wg set {$escapedInterface} peer {$escapedPubkey} remove");

        // Remove client config if it exists
        if ($targetIp !== null) {
            $configPath = $this->os->configPath();
            $clientFile = "{$configPath}/clients/{$interfaceName}/{$targetIp}.conf";
            if (file_exists($clientFile)) {
                @unlink($clientFile);
            }
        }
    }

    public function getPeerConfig(string $interfaceName, string $ip): ?string
    {
        $configPath = $this->os->configPath();
        $clientFile = "{$configPath}/clients/{$interfaceName}/{$ip}.conf";

        if (! file_exists($clientFile)) {
            return null;
        }

        return file_get_contents($clientFile);
    }

    // ─── Private helpers ─────────────────────────────────────────────

    private function readIfoutFromConfig(string $name): ?string
    {
        $configPath = $this->os->configPath();
        $configFile = "{$configPath}/{$name}.conf";

        if (! file_exists($configFile)) {
            return null;
        }

        $content = @file_get_contents($configFile);
        if ($content === false) {
            // Try with sudo
            $content = $this->shell->tryRun('sudo cat '.escapeshellarg($configFile));
            if ($content === null) {
                return null;
            }
        }

        // Match POSTROUTING -o <ifout> or "nat on <ifout>"
        if (preg_match('/POSTROUTING\s+-o\s+(\S+)/', $content, $matches)) {
            return $matches[1];
        }

        if (preg_match('/nat on (\S+)/', $content, $matches)) {
            return $matches[1];
        }

        return null;
    }

    private function buildClientConfig(InterfaceInfo $interface, string $privkey, string $ip, string $pubkey, string $psk): string
    {
        $dns = $this->config['default_dns'] ?? '8.8.8.8';
        $keepalive = $this->config['default_keepalive'] ?? 25;
        $allowedIps = $this->config['allowed_ips'] ?? '0.0.0.0/0';
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

    private function saveClientConfig(string $interfaceName, string $ip, string $config): void
    {
        $configPath = $this->os->configPath();
        $clientDir = "{$configPath}/clients/{$interfaceName}";

        if (! is_dir($clientDir)) {
            $this->shell->tryRun('sudo mkdir -p '.escapeshellarg($clientDir));
        }

        $clientFile = "{$clientDir}/{$ip}.conf";

        // Write securely via temp file
        $tmpFile = tempnam(sys_get_temp_dir(), 'wg_client_');
        file_put_contents($tmpFile, $config."\n");
        $this->shell->tryRun('sudo cp '.escapeshellarg($tmpFile).' '.escapeshellarg($clientFile));
        @unlink($tmpFile);
    }
}
