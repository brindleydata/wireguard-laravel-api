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
        return base64_encode(\sodium_crypto_scalarmult_base(base64_decode($privkey)));
    }

    // ─── Link operations ──────────────────────────────────────────────

    public function listLinks(): array
    {
        $running = $this->runningLinks();
        $persisted = $this->os->listConfigNames();

        return array_values(array_unique(array_merge($running, $persisted)));
    }

    public function isRunning(string $name): bool
    {
        return in_array($name, $this->runningLinks());
    }

    protected function runningLinks(): array
    {
        $output = $this->shell->tryRun('sudo wg show interfaces');
        if ($output === null || $output === '') {
            return [];
        }

        return preg_split('/\s+/', trim($output));
    }

    public function getLink(string $name): ?InterfaceInfo
    {
        $is_running = $this->isRunning($name);

        if ($is_running) {
            return $this->getLinkFromRuntime($name);
        }

        return $this->getLinkFromConfig($name);
    }

    protected function getLinkFromRuntime(string $name): ?InterfaceInfo
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

        // Get ifout and forward/nat from conf metadata
        $meta = $meta ?? $this->os->parseConfig($name);
        $ifout = $meta['ifout'] ?? $this->os->defaultOutboundInterface();
        $forward = ($meta['forward'] ?? 'false') === 'true';
        $nat = ($meta['nat'] ?? 'false') === 'true';

        // Build peer list from lines 2+
        $peers = [];
        for ($i = 1; $i < count($lines); $i++) {
            $parts = explode("\t", $lines[$i]);
            if (count($parts) < 4) {
                continue;
            }

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
            forward: $forward,
            nat: $nat,
            up: true,
            peers: $peers,
        );
    }

    protected function getLinkFromConfig(string $name): ?InterfaceInfo
    {
        $content = $this->os->readConfig($name);
        if ($content === null) {
            return null;
        }

        $parsed = $this->parseConfContent($content);
        $metadata = $parsed['metadata'];
        $interface = $parsed['interface'];

        $private_key = $interface['PrivateKey'] ?? '';
        $public_key = $private_key !== '' ? $this->pubkey($private_key) : '';
        $listen_port = (int) ($interface['ListenPort'] ?? 0);
        $address = $metadata['address'] ?? $interface['Address'] ?? '(none)';
        $ifout = $metadata['ifout'] ?? $this->os->defaultOutboundInterface();
        $forward = ($metadata['forward'] ?? 'false') === 'true';
        $nat = ($metadata['nat'] ?? 'false') === 'true';

        $peers = [];
        foreach ($parsed['peers'] as $peer_data) {
            $peers[] = new PeerInfo(
                public_key: $peer_data['PublicKey'] ?? '',
                preshared_key: $peer_data['PresharedKey'] ?? null,
                allowed_ips: $peer_data['AllowedIPs'] ?? '',
            );
        }

        return new InterfaceInfo(
            name: $name,
            public_key: $public_key,
            private_key: $private_key,
            listen_port: $listen_port,
            address: $address,
            ifout: $ifout,
            forward: $forward,
            nat: $nat,
            up: false,
            peers: $peers,
        );
    }

    public function createLink(string $name, string $ip, ?int $port = null, ?string $ifout = null, ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        if (str_contains($ip, '/')) {
            $this->validator->validateCidr($ip);
        } else {
            $this->validator->validateIpAddress($ip);
        }

        if (in_array($name, $this->listLinks())) {
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
        $content = $this->buildConfFile($address, $privkey, $port, $ifout, [], $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
        $this->os->writeConfig($name, $content);

        if ($up) {
            try {
                $this->os->startInterface($name);
            } catch (\Throwable $e) {
                $this->os->deleteConfig($name);

                throw new RuntimeException("Failed to create link {$name}: {$e->getMessage()}", 0, $e);
            }
        }

        return new InterfaceInfo(
            name: $name,
            public_key: $pubkey,
            private_key: $privkey,
            listen_port: $port,
            address: $address,
            ifout: $ifout,
            forward: $forward,
            nat: $nat,
            up: $up,
        );
    }

    public function deleteLink(string $name): void
    {
        $this->validator->validateInterfaceName($name);

        $is_running = $this->isRunning($name);

        if (! $is_running && ! $this->os->configExists($name)) {
            throw new NotFoundException("Link does not exist: {$name}");
        }

        // Clean up forward/nat rules before stopping
        $meta = $this->os->parseConfig($name);
        if ($meta !== null && $is_running) {
            $forward = ($meta['forward'] ?? 'false') === 'true';
            $nat = ($meta['nat'] ?? 'false') === 'true';
            $ifout = $meta['ifout'] ?? $this->os->defaultOutboundInterface();

            if ($forward) {
                $this->os->disableForward($name);
            }
            if ($nat) {
                $this->os->disableNat($name, $ifout);
            }
        }

        // Stop the interface if running
        if ($is_running) {
            $this->os->stopInterface($name);
        }

        $this->os->deleteConfig($name);
        $this->os->deleteClientConfigDir($name);
    }

    // ─── Key encoding helpers ──────────────────────────────────────────

    public static function pubkeyToSafe(string $pubkey): string
    {
        return rtrim(strtr($pubkey, '+/', '-_'), '=');
    }

    public static function safeToPubkey(string $safe): string
    {
        return strtr($safe, '-_', '+/').str_repeat('=', (4 - strlen($safe) % 4) % 4);
    }

    // ─── Peer operations ─────────────────────────────────────────────

    public function findAvailableIp(string $interface_address, array $existing_peers): string
    {
        if (! str_contains($interface_address, '/')) {
            throw new RuntimeException("Interface address must include CIDR notation: {$interface_address}");
        }

        [$network_ip, $mask] = explode('/', $interface_address, 2);
        $mask = (int) $mask;

        $network_long = ip2long($network_ip);
        $host_bits = 32 - $mask;
        $network_start = $network_long & ((-1 << $host_bits) & 0xFFFFFFFF);
        $network_end = $network_start | ((1 << $host_bits) - 1);

        // Collect all used IPs (interface address + existing peers)
        $used = [];
        $used[ip2long($network_ip)] = true;
        $used[$network_start] = true;       // network address
        $used[$network_end] = true;         // broadcast address

        foreach ($existing_peers as $peer) {
            $peer_ip = explode('/', $peer->allowed_ips, 2)[0];
            $used[ip2long($peer_ip)] = true;
        }

        // Find first available host
        for ($ip = $network_start + 1; $ip < $network_end; $ip++) {
            if (! isset($used[$ip])) {
                return long2ip($ip);
            }
        }

        throw new RuntimeException('No available IP addresses in subnet.');
    }

    public function addPeer(string $link_name, ?string $ip = null): PeerInfo
    {
        $link = $this->getLink($link_name);
        if ($link === null) {
            throw new NotFoundException("Link does not exist: {$link_name}");
        }

        // Auto-assign IP if not provided
        if ($ip === null || $ip === '') {
            $bare_ip = $this->findAvailableIp($link->address, $link->peers);
            $mask = '32';
        } elseif (str_contains($ip, '/')) {
            [$bare_ip, $mask] = explode('/', $ip, 2);
        } else {
            $bare_ip = $ip;
            $mask = '32';
        }

        // Validate peer IP
        $existing_ips = array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers);
        $this->validator->validateNewPeerIp($bare_ip, $link->address, $existing_ips);

        // Generate keys (base64)
        $privkey = $this->genkey();
        $pubkey = $this->pubkey($privkey);
        $psk = $this->genpsk();

        $allowed_ips = "{$bare_ip}/{$mask}";

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
        $client_config = $this->buildClientConfig($link, $privkey, $bare_ip, $pubkey, $psk);

        // Save client config keyed by base64url-safe pubkey
        $this->os->writeClientConfig($link_name, self::pubkeyToSafe($pubkey), $client_config);

        return new PeerInfo(
            public_key: $pubkey,
            preshared_key: $psk,
            allowed_ips: $allowed_ips,
            private_key: $privkey,
            client_config: $client_config,
        );
    }

    public function removePeer(string $link_name, string $pubkey): void
    {
        $link = $this->getLink($link_name);
        if ($link === null) {
            throw new NotFoundException("Link does not exist: {$link_name}");
        }

        $target = null;
        foreach ($link->peers as $peer) {
            if ($peer->public_key === $pubkey) {
                $target = $peer;
                break;
            }
        }

        if ($target === null) {
            throw new NotFoundException("Peer not found: {$pubkey}");
        }

        // Remove peer via wg set
        $this->shell->run('sudo wg set :name peer :pubkey remove', ['name' => $link_name, 'pubkey' => $pubkey]);

        // Rebuild conf file without the removed peer
        $this->rebuildConfWithPeers($link_name);

        // Delete client config file
        $this->os->deleteClientConfig($link_name, self::pubkeyToSafe($pubkey));
    }

    public function getPeerConfig(string $link_name, string $pubkey): ?string
    {
        return $this->os->readClientConfig($link_name, self::pubkeyToSafe($pubkey));
    }

    // ─── Update operations ──────────────────────────────────────────

    public function updateLink(string $name, array $params): InterfaceInfo
    {
        $this->validator->validateInterfaceName($name);

        if (! in_array($name, $this->listLinks())) {
            throw new NotFoundException("Link does not exist: {$name}");
        }

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
        if (isset($params['ifout'])) {
            $system_interfaces = $this->os->networkInterfaces();
            if (! in_array($params['ifout'], $system_interfaces)) {
                throw new RuntimeException("Output interface does not exist: {$params['ifout']}");
            }
        }

        $is_running = $this->isRunning($name);

        // Read current config metadata
        $meta = $this->os->parseConfig($name) ?? [];
        $current_forward = ($meta['forward'] ?? 'false') === 'true';
        $current_nat = ($meta['nat'] ?? 'false') === 'true';
        $current_ifout = $meta['ifout'] ?? $this->os->defaultOutboundInterface();

        // Determine target states
        $new_forward = array_key_exists('forward', $params) ? (bool) $params['forward'] : $current_forward;
        $new_nat = array_key_exists('nat', $params) ? (bool) $params['nat'] : $current_nat;
        $new_ifout = $params['ifout'] ?? $current_ifout;
        $target_up = array_key_exists('up', $params) ? (bool) $params['up'] : $is_running;

        // Build metadata overrides (only for fields that were provided)
        $overrides = [];
        foreach (['dns', 'keepalive', 'allowed_ips', 'ifout', 'address'] as $field) {
            if (array_key_exists($field, $params)) {
                $overrides[$field] = (string) $params[$field];
            }
        }
        if (isset($params['port'])) {
            $overrides['port'] = (string) $params['port'];
        }
        if (array_key_exists('forward', $params)) {
            $overrides['forward'] = $new_forward ? 'true' : 'false';
        }
        if (array_key_exists('nat', $params)) {
            $overrides['nat'] = $new_nat ? 'true' : 'false';
        }
        if (array_key_exists('up', $params)) {
            $overrides['up'] = $target_up ? 'true' : 'false';
        }

        $has_config_changes = isset($params['address']) || isset($params['port']);
        $needs_restart = $is_running && $target_up && $has_config_changes;

        if ($needs_restart) {
            // Running and staying up with address/port change — full restart
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

            // Clean up runtime forward/nat rules before stopping
            if ($current_forward) {
                $this->os->disableForward($name);
            }
            if ($current_nat) {
                $this->os->disableNat($name, $current_ifout);
            }

            $this->os->stopInterface($name);

            $content = $this->os->readConfig($name);
            $parsed = $this->parseConfContent($content);
            $metadata = array_merge($parsed['metadata'], $overrides);
            $interface = $parsed['interface'];

            $address = $params['address'] ?? $metadata['address'] ?? $interface['Address'] ?? '';
            $privkey = $interface['PrivateKey'] ?? '';
            $port = isset($params['port']) ? (int) $params['port'] : (int) ($interface['ListenPort'] ?? 0);
            $ifout = $metadata['ifout'] ?? $this->os->defaultOutboundInterface();
            $forward = ($metadata['forward'] ?? 'false') === 'true';
            $nat = ($metadata['nat'] ?? 'false') === 'true';
            $up = ($metadata['up'] ?? 'true') === 'true';
            $dns = $metadata['dns'] ?? null;
            $keepalive = isset($metadata['keepalive']) ? (int) $metadata['keepalive'] : null;
            $allowed_ips = $metadata['allowed_ips'] ?? null;

            $new_content = $this->buildConfFile($address, $privkey, $port, $ifout, $peers, $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
            $this->os->writeConfig($name, $new_content);

            $this->os->startInterface($name);
        } else {
            // Apply forward/nat runtime changes (only while running and staying up)
            if ($is_running && $target_up) {
                if (array_key_exists('forward', $params) && $new_forward !== $current_forward) {
                    if ($new_forward) {
                        $this->os->enableForward($name);
                    } else {
                        $this->os->disableForward($name);
                    }
                }

                $nat_toggled = array_key_exists('nat', $params) && $new_nat !== $current_nat;
                $ifout_changed = isset($params['ifout']) && $params['ifout'] !== $current_ifout;

                if ($nat_toggled || ($ifout_changed && $current_nat)) {
                    if ($current_nat) {
                        $this->os->disableNat($name, $current_ifout);
                    }
                    if ($new_nat) {
                        $this->os->enableNat($name, $new_ifout);
                    }
                }
            }

            // Rebuild conf with all overrides (handles both running and stopped links)
            if (! empty($overrides)) {
                $this->rebuildConfWithOverrides($name, $overrides);
            }

            // Handle up state transitions
            if ($target_up && ! $is_running) {
                $this->os->startInterface($name);
            } elseif (! $target_up && $is_running) {
                if ($current_forward) {
                    $this->os->disableForward($name);
                }
                if ($current_nat) {
                    $this->os->disableNat($name, $current_ifout);
                }
                $this->os->stopInterface($name);
            }
        }

        return $this->getLink($name);
    }

    public function updatePeer(string $link_name, string $pubkey, array $params): PeerInfo
    {
        $link = $this->getLink($link_name);
        if ($link === null) {
            throw new NotFoundException("Link does not exist: {$link_name}");
        }

        $target = null;
        foreach ($link->peers as $peer) {
            if ($peer->public_key === $pubkey) {
                $target = $peer;
                break;
            }
        }
        if ($target === null) {
            throw new NotFoundException("Peer not found: {$pubkey}");
        }

        // Update server-side AllowedIPs if requested
        $allowed_ips = $target->allowed_ips;
        if (isset($params['allowed_ips'])) {
            $allowed_ips = $params['allowed_ips'];
            $this->shell->run('sudo wg set :link peer :pubkey allowed-ips :ips', [
                'link' => $link_name,
                'pubkey' => $pubkey,
                'ips' => $allowed_ips,
            ]);
            $this->rebuildConfWithPeers($link_name);
        }

        // Read stored client config to extract keys for regeneration
        $safe = self::pubkeyToSafe($pubkey);
        $client_content = $this->os->readClientConfig($link_name, $safe);
        if ($client_content === null) {
            throw new NotFoundException("Client config not found for peer: {$pubkey}");
        }

        $client = $this->parseClientConfig($client_content);

        // Rebuild client config with overrides
        $new_client_config = $this->buildClientConfig(
            $link,
            $client['PrivateKey'],
            $client['Address'],
            $pubkey,
            $client['PresharedKey'],
            $params['dns'] ?? null,
            $params['allowed_ips'] ?? null,
        );
        $this->os->writeClientConfig($link_name, $safe, $new_client_config);

        return new PeerInfo(
            public_key: $pubkey,
            preshared_key: $client['PresharedKey'],
            allowed_ips: $allowed_ips,
            client_config: $new_client_config,
        );
    }

    protected function parseClientConfig(string $content): array
    {
        $result = [];
        $section = null;

        foreach (explode("\n", $content) as $line) {
            $line = trim($line);
            if ($line === '[Interface]') {
                $section = 'interface';

                continue;
            }
            if ($line === '[Peer]') {
                $section = 'peer';

                continue;
            }
            if (preg_match('/^(\S+)\s*=\s*(.+)$/', $line, $m)) {
                $key = $m[1];
                $value = trim($m[2]);
                if ($section === 'interface' && $key === 'PrivateKey') {
                    $result['PrivateKey'] = $value;
                }
                if ($section === 'interface' && $key === 'Address') {
                    $result['Address'] = explode('/', $value, 2)[0];
                }
                if ($section === 'peer' && $key === 'PresharedKey') {
                    $result['PresharedKey'] = $value;
                }
            }
        }

        return $result;
    }

    // ─── Private helpers ─────────────────────────────────────────────

    protected function buildConfFile(string $address, string $privkey, int $port, string $ifout, array $peers = [], ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true): string
    {
        // Metadata comments (address and ifout always written)
        $lines = [];
        $lines[] = "# address = {$address}";
        $lines[] = "# ifout = {$ifout}";
        $lines[] = '# forward = '.($forward ? 'true' : 'false');
        $lines[] = '# nat = '.($nat ? 'true' : 'false');
        $lines[] = '# up = '.($up ? 'true' : 'false');
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
        $lines[] = $this->os->interfaceSection($address, $privkey, $port, $ifout, $forward, $nat);

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
        $forward = ($metadata['forward'] ?? 'false') === 'true';
        $nat = ($metadata['nat'] ?? 'false') === 'true';
        $up = ($metadata['up'] ?? 'true') === 'true';
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

        $new_content = $this->buildConfFile($address, $privkey, $port, $ifout, $peers, $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
        $this->os->writeConfig($name, $new_content);
    }

    protected function rebuildConfWithOverrides(string $name, array $overrides): void
    {
        $content = $this->os->readConfig($name);
        if ($content === null) {
            return;
        }

        $parsed = $this->parseConfContent($content);
        $metadata = array_merge($parsed['metadata'], $overrides);
        $interface = $parsed['interface'];

        $address = $metadata['address'] ?? $interface['Address'] ?? '';
        $privkey = $interface['PrivateKey'] ?? '';
        $port = isset($metadata['port']) ? (int) $metadata['port'] : (int) ($interface['ListenPort'] ?? 0);
        $ifout = $metadata['ifout'] ?? $this->os->defaultOutboundInterface();
        $forward = ($metadata['forward'] ?? 'false') === 'true';
        $nat = ($metadata['nat'] ?? 'false') === 'true';
        $up = ($metadata['up'] ?? 'true') === 'true';
        $dns = $metadata['dns'] ?? null;
        $keepalive = isset($metadata['keepalive']) ? (int) $metadata['keepalive'] : null;
        $allowed_ips = $metadata['allowed_ips'] ?? null;

        // Get peers from runtime if running, otherwise from config file
        $peers = [];
        if ($this->isRunning($name)) {
            $output = $this->shell->tryRun('sudo wg show :name dump', ['name' => $name]);
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
        } else {
            foreach ($parsed['peers'] as $peer_data) {
                $peer = [
                    'public_key' => $peer_data['PublicKey'] ?? '',
                    'allowed_ips' => $peer_data['AllowedIPs'] ?? '',
                ];
                if (! empty($peer_data['PresharedKey'])) {
                    $peer['preshared_key'] = $peer_data['PresharedKey'];
                }
                $peers[] = $peer;
            }
        }

        $new_content = $this->buildConfFile($address, $privkey, $port, $ifout, $peers, $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
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

    protected function buildClientConfig(InterfaceInfo $link, string $privkey, string $ip, string $pubkey, string $psk, ?string $dns_override = null, ?string $allowed_ips_override = null): string
    {
        // Per-interface overrides from conf metadata, falling back to global defaults
        $meta = $this->os->parseConfig($link->name) ?? [];
        $dns = $dns_override ?? $meta['dns'] ?? $this->config['default_dns'] ?? '8.8.8.8';
        $keepalive = $meta['keepalive'] ?? $this->config['default_keepalive'] ?? 25;
        $allowed_ips = $allowed_ips_override ?? $meta['allowed_ips'] ?? $this->config['allowed_ips'] ?? '0.0.0.0/0';
        $endpoint_host = $this->config['hostname'] ?? null;
        if ($endpoint_host === null || $endpoint_host === '') {
            $hostname = gethostname();
            // Use gethostname() only if it looks like a reachable FQDN or IP
            if (filter_var($hostname, FILTER_VALIDATE_IP) || str_contains($hostname, '.')) {
                $endpoint_host = $hostname;
            } else {
                $ip_service = $this->config['ip_service'] ?? 'http://ifconfig.me/ip';
                $endpoint_host = $this->os->publicIpv4($ip_service) ?? $hostname;
            }
        }
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
