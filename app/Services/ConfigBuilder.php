<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\Services\Os\OsDriver;

class ConfigBuilder
{
    public function __construct(
        protected array $config,
        protected OsDriver $os,
    ) {}

    public function buildConfFile(string $address, string $privkey, int $port, string $ifout, array $peers = [], ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true): string
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

    public function buildClientConfig(InterfaceInfo $link, string $privkey, string $ip, string $pubkey, string $psk, ?string $dns_override = null, ?string $allowed_ips_override = null, ?array $metadata = null): string
    {
        // Per-interface overrides from conf metadata, falling back to global defaults
        $meta = $metadata ?? $this->os->parseConfig($link->name) ?? [];
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

    public function parseConfContent(string $content): array
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

    public static function parseMetadata(string $content): array
    {
        $metadata = [];
        foreach (explode("\n", $content) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] !== '#') {
                break;
            }
            if (preg_match('/^#\s*(\w+)\s*=\s*(.+)$/', $line, $matches)) {
                $metadata[trim($matches[1])] = trim($matches[2]);
            }
        }

        return $metadata;
    }

    public function parseClientConfig(string $content): array
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
}
