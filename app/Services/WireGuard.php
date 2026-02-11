<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\DTOs\PeerInfo;
use App\Exceptions\NotFoundException;
use App\Services\Os\OsDriver;
use App\Validation\WireGuardValidator;
use RuntimeException;

class WireGuard
{
    public function __construct(
        protected array $config,
        protected OsDriver $os,
        protected WireGuardValidator $validator,
        protected Shell $shell,
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

    // ─── Link operations ──────────────────────────────────────────────

    public function listLinks(): array
    {
        $output = $this->shell->tryRun('sudo wg show interfaces');
        if ($output === null || $output === '') {
            return [];
        }

        return preg_split('/\s+/', trim($output));
    }

    public function getLink(string $name): ?InterfaceInfo
    {
        $output = $this->shell->tryRun('sudo wg show :name dump', ['name' => $name]);
        if ($output === null || $output === '') {
            return null;
        }

        $lines = explode("\n", trim($output));
        if ($lines === []) {
            return null;
        }

        // Line 1: private_key, public_key, listen_port, fwmark (tab-separated)
        $iface_parts = explode("\t", $lines[0]);
        $private_key = $iface_parts[0] ?? '';
        $public_key = $private_key !== '' && $private_key !== '(none)' ? $this->pubkey($private_key) : '';
        $listen_port = (int) ($iface_parts[2] ?? 0);

        // Get address from OS, fallback to conf metadata
        $address = $this->os->interfaceAddress($name);
        if ($address === null) {
            $meta = $this->os->parseConfig($name);
            $address = $meta['address'] ?? '(none)';
        }

        // Get ifout from conf metadata
        $meta = $meta ?? $this->os->parseConfig($name);
        $ifout = $meta['ifout'] ?? $this->os->defaultOutboundInterface();

        // Build peer list from lines 2+
        $peers = [];
        for ($i = 1; $i < count($lines); $i++) {
            $parts = explode("\t", $lines[$i]);
            if (count($parts) < 4) {
                continue;
            }

            // peer: public_key, preshared_key, endpoint, allowed_ips, latest_handshake, rx, tx, keepalive
            $peer_pubkey = $parts[0];
            $peer_psk = ($parts[1] ?? '(none)') !== '(none)' ? $parts[1] : null;
            $allowed_ips = $parts[3] ?? '';

            $peers[] = new PeerInfo(
                public_key: $peer_pubkey,
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

    public function createLink(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);
        $this->validator->validateIpAddress($ip);

        if ($this->os->configExists($name) || in_array($name, $this->listLinks())) {
            throw new RuntimeException("Link already exists: {$name}");
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

        // Build and write conf file with metadata comments
        $content = $this->buildConfFile($address, $privkey, $port, $ifout, [], $dns, $keepalive, $allowed_ips);
        $this->os->writeConfig($name, $content);

        try {
            $this->os->startInterface($name);
        } catch (\Throwable $e) {
            $this->os->deleteConfig($name);

            throw new RuntimeException("Failed to create link {$name}: {$e->getMessage()}", 0, $e);
        }

        return new InterfaceInfo(
            name: $name,
            public_key: $pubkey,
            private_key: $privkey,
            listen_port: $port,
            address: $address,
            ifout: $ifout,
        );
    }

    public function deleteLink(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $is_running = in_array($name, $this->listLinks());
        $has_config = $this->os->configExists($name);

        if (! $is_running && ! $has_config) {
            throw new NotFoundException("Link does not exist: {$name}");
        }

        // Stop the interface if running
        if ($is_running) {
            $this->os->stopInterface($name);
        }

        $this->os->deleteConfig($name);
        $this->os->deleteClientConfigDir($name);
    }

    // ─── Lifecycle (up / down) ──────────────────────────────────────

    public function linkUp(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        if (! $this->os->configExists($name)) {
            throw new NotFoundException("Link config does not exist: {$name}");
        }

        if (in_array($name, $this->listLinks())) {
            throw new RuntimeException("Link is already running: {$name}");
        }

        $this->os->startInterface($name);
    }

    public function linkDown(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        if (! in_array($name, $this->listLinks())) {
            throw new NotFoundException("Link is not running: {$name}");
        }

        $this->os->stopInterface($name);
    }

    // ─── Peer operations ─────────────────────────────────────────────

    public function addPeer(string $link_name, string $ip): PeerInfo
    {
        $link = $this->getLink($link_name);
        if ($link === null) {
            throw new NotFoundException("Link does not exist: {$link_name}");
        }

        // Validate peer IP
        $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers);
        $this->validator->validateNewPeerIp($ip, $link->address, $existing_ips);

        // Generate keys (base64)
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);
        $psk = $this->genpsk();

        $allowed_ips = "{$ip}/32";

        // Write peer config to temp file and apply via wg addconf
        $peer_conf = implode("\n", [
            '[Peer]',
            "PublicKey = {$pubkey}",
            "PresharedKey = {$psk}",
            "AllowedIPs = {$allowed_ips}",
        ]);

        $tmp = tempnam(sys_get_temp_dir(), 'wg_peer_');
        file_put_contents($tmp, $peer_conf."\n");

        try {
            $this->shell->run('sudo wg addconf :name :tmp', ['name' => $link_name, 'tmp' => $tmp]);
        } finally {
            @unlink($tmp);
        }

        // Rebuild conf file with new peer appended
        $this->rebuildConfWithPeers($link_name);

        // Build client config
        $client_config = $this->buildClientConfig($link, $privkey, $ip, $pubkey, $psk);

        // Save client config via OS driver
        $this->os->writeClientConfig($link_name, $ip, $client_config);

        return new PeerInfo(
            public_key: $pubkey,
            preshared_key: $psk,
            allowed_ips: $allowed_ips,
            private_key: $privkey,
            client_config: $client_config,
        );
    }

    public function removePeer(string $link_name, string $peer_identifier): void
    {
        $link = $this->getLink($link_name);
        if ($link === null) {
            throw new NotFoundException("Link does not exist: {$link_name}");
        }

        $target_pubkey = null;
        $target_ip = null;
        foreach ($link->peers as $peer) {
            $peer_ip_clean = str_replace('/32', '', $peer->allowed_ips);
            if ($peer->public_key === $peer_identifier || $peer_ip_clean === $peer_identifier) {
                $target_pubkey = $peer->public_key;
                $target_ip = $peer_ip_clean;
                break;
            }
        }

        if ($target_pubkey === null) {
            throw new NotFoundException("Peer not found: {$peer_identifier}");
        }

        // Remove peer via wg set
        $this->shell->run('sudo wg set :name peer :pubkey remove', ['name' => $link_name, 'pubkey' => $target_pubkey]);

        // Rebuild conf file without the removed peer
        $this->rebuildConfWithPeers($link_name);

        // Delete client config file
        if ($target_ip !== null) {
            $this->os->deleteClientConfig($link_name, $target_ip);
        }
    }

    public function getPeerConfig(string $link_name, string $ip): ?string
    {
        return $this->os->readClientConfig($link_name, $ip);
    }

    // ─── Private helpers ─────────────────────────────────────────────

    protected function buildConfFile(string $address, string $privkey, int $port, string $ifout, array $peers = [], ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null): string
    {
        // Metadata comments (address and ifout always written)
        $lines = [];
        $lines[] = "# address = {$address}";
        $lines[] = "# ifout = {$ifout}";
        if ($dns !== null) {
            $lines[] = "# dns = {$dns}";
        }
        if ($keepalive !== null) {
            $lines[] = "# keepalive = {$keepalive}";
        }
        if ($allowed_ips !== null) {
            $lines[] = "# allowed_ips = {$allowed_ips}";
        }

        // Interface section from OS driver
        $lines[] = $this->os->interfaceSection($address, $privkey, $port, $ifout);

        // Peer sections
        foreach ($peers as $peer) {
            $lines[] = '';
            $lines[] = '[Peer]';
            $lines[] = "PublicKey = {$peer['public_key']}";
            if (! empty($peer['preshared_key'])) {
                $lines[] = "PresharedKey = {$peer['preshared_key']}";
            }
            $lines[] = "AllowedIPs = {$peer['allowed_ips']}";
        }

        return implode("\n", $lines);
    }

    protected function rebuildConfWithPeers(string $name): void
    {
        // Read current conf to get metadata and interface details
        $content = $this->os->readConfig($name);
        if ($content === null) {
            return;
        }

        $parsed = $this->parseConfContent($content);
        $metadata = $parsed['metadata'];
        $interface = $parsed['interface'];

        $address = $metadata['address'] ?? $interface['Address'] ?? '';
        $privkey = $interface['PrivateKey'] ?? '';
        $port = (int) ($interface['ListenPort'] ?? 0);
        $ifout = $metadata['ifout'] ?? $this->os->defaultOutboundInterface();
        $dns = $metadata['dns'] ?? null;
        $keepalive = isset($metadata['keepalive']) ? (int) $metadata['keepalive'] : null;
        $allowed_ips = $metadata['allowed_ips'] ?? null;

        // Get current peers from running interface (source of truth after wg addconf/set)
        $output = $this->shell->tryRun('sudo wg show :name dump', ['name' => $name]);
        $peers = [];
        if ($output !== null && $output !== '') {
            $lines = explode("\n", trim($output));
            for ($i = 1; $i < count($lines); $i++) {
                $parts = explode("\t", $lines[$i]);
                if (count($parts) < 4) {
                    continue;
                }
                $peer = [
                    'public_key' => $parts[0],
                    'allowed_ips' => $parts[3] ?? '',
                ];
                if (($parts[1] ?? '(none)') !== '(none)') {
                    $peer['preshared_key'] = $parts[1];
                }
                $peers[] = $peer;
            }
        }

        $new_content = $this->buildConfFile($address, $privkey, $port, $ifout, $peers, $dns, $keepalive, $allowed_ips);
        $this->os->writeConfig($name, $new_content);
    }

    protected function parseConfContent(string $content): array
    {
        $metadata = [];
        $interface = [];
        $peers = [];
        $current_section = null;

        foreach (explode("\n", $content) as $line) {
            $trimmed = trim($line);

            // Metadata comments (only before [Interface])
            if ($current_section === null && str_starts_with($trimmed, '#')) {
                if (preg_match('/^#\s*(\w+)\s*=\s*(.+)$/', $trimmed, $matches)) {
                    $metadata[trim($matches[1])] = trim($matches[2]);
                }

                continue;
            }

            if ($trimmed === '[Interface]') {
                $current_section = 'interface';

                continue;
            }

            if ($trimmed === '[Peer]') {
                $current_section = 'peer';
                $peers[] = [];

                continue;
            }

            if ($trimmed === '') {
                continue;
            }

            if (preg_match('/^(\S+)\s*=\s*(.+)$/', $trimmed, $matches)) {
                $key = $matches[1];
                $value = trim($matches[2]);

                if ($current_section === 'interface') {
                    $interface[$key] = $value;
                } elseif ($current_section === 'peer' && $peers !== []) {
                    $peers[count($peers) - 1][$key] = $value;
                }
            }
        }

        return [
            'metadata' => $metadata,
            'interface' => $interface,
            'peers' => $peers,
        ];
    }

    protected function buildClientConfig(InterfaceInfo $link, string $privkey, string $ip, string $pubkey, string $psk): string
    {
        // Per-interface overrides from conf metadata, falling back to global defaults
        $meta = $this->os->parseConfig($link->name) ?? [];
        $dns = $meta['dns'] ?? $this->config['default_dns'] ?? '8.8.8.8';
        $keepalive = $meta['keepalive'] ?? $this->config['default_keepalive'] ?? 25;
        $allowed_ips = $meta['allowed_ips'] ?? $this->config['allowed_ips'] ?? '0.0.0.0/0';
        $endpoint_host = $this->config['hostname'] ?? gethostname();
        $endpoint = "{$endpoint_host}:{$link->listen_port}";

        $template = $this->config['templates']['client'] ?? null;
        if ($template !== null) {
            return str_replace(
                ['{privkey}', '{pubkey}', '{psk}', '{subnets}', '{keepalive}', '{dns}', '{endpoint}', '{ip}'],
                [$privkey, $link->public_key, $psk, $allowed_ips, $keepalive, $dns, $endpoint, $ip],
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
            "PublicKey = {$link->public_key}",
            "PresharedKey = {$psk}",
            "AllowedIPs = {$allowed_ips}",
            "Endpoint = {$endpoint}",
            "PersistentKeepalive = {$keepalive}",
        ]);
    }
}
