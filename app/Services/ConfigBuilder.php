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

    public function buildConfFile(string $address, string $privkey, int $port, string $ifout, array $peers = [], ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true, ?string $address6 = null): string
    {
        // Metadata comments (address and ifout always written)
        $lines = [];
        $lines[] = "# address = {$address}";
        if ($address6 !== null) {
            $lines[] = "# address6 = {$address6}";
        }
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
        $lines[] = $this->os->interfaceSection($address6 === null ? $address : "{$address}, {$address6}", $privkey, $port, $ifout, $forward, $nat);

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

    /**
     * Client config values a link hands out unless a peer overrides them: the link's own metadata
     * (dns, keepalive, allowed_ips), falling back to the global WIREGUARD_* defaults.
     *
     * A dual-stack link sends all IPv6 traffic through the tunnel too: when the global default
     * routes all IPv4 (0.0.0.0/0) and names no IPv6, ::/0 is added.
     *
     * @return array{dns: string, keepalive: string, allowed_ips: string}
     */
    public function clientDefaults(array $metadata): array
    {
        $allowed_ips = (string) ($metadata['allowed_ips'] ?? $this->config['allowed_ips'] ?? '0.0.0.0/0');
        if (! isset($metadata['allowed_ips']) && isset($metadata['address6'])
            && in_array('0.0.0.0/0', array_map('trim', explode(',', $allowed_ips)), true) && ! str_contains($allowed_ips, ':')) {
            $allowed_ips .= ', ::/0';
        }

        return [
            'dns' => (string) ($metadata['dns'] ?? $this->config['default_dns'] ?? '8.8.8.8'),
            'keepalive' => (string) ($metadata['keepalive'] ?? $this->config['default_keepalive'] ?? 25),
            'allowed_ips' => $allowed_ips,
        ];
    }

    /**
     * The client's Address line: its IPv4 /32, plus the mirrored IPv6 /128 on a dual-stack link.
     */
    public function clientAddress(InterfaceInfo $link, string $ip): string
    {
        return $link->address6 === null
            ? "{$ip}/32"
            : "{$ip}/32, ".IpAllocator::mirror($ip, $link->address, $link->address6).'/128';
    }

    public function buildClientConfig(InterfaceInfo $link, string $privkey, string $ip, string $pubkey, string $psk, ?string $dns_override = null, ?string $allowed_ips_override = null, ?array $metadata = null, ?string $keepalive_override = null): string
    {
        $defaults = $this->clientDefaults($metadata ?? $this->os->parseConfig($link->name) ?? []);
        $dns = $dns_override ?? $defaults['dns'];
        $keepalive = $keepalive_override ?? $defaults['keepalive'];
        $allowed_ips = $allowed_ips_override ?? $defaults['allowed_ips'];
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
        // An IPv6 literal needs brackets before the port
        $endpoint = filter_var($endpoint_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)
            ? "[{$endpoint_host}]:{$link->listen_port}"
            : "{$endpoint_host}:{$link->listen_port}";
        $address = $this->clientAddress($link, $ip);

        $template = $this->config['templates']['client'] ?? null;
        if ($template !== null) {
            // {address}: the Address value (both families); {ip}: the bare IPv4 tunnel address
            return str_replace(
                ['{privkey}', '{pubkey}', '{psk}', '{subnets}', '{keepalive}', '{dns}', '{endpoint}', '{address}', '{ip}'],
                [$privkey, $link->public_key, $psk, $allowed_ips, $keepalive, $dns, $endpoint, $address, $ip],
                $template,
            );
        }

        return implode("\n", [
            '[Interface]',
            "PrivateKey = {$privkey}",
            "Address = {$address}",
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
                if ($section === 'interface' && in_array($key, ['PrivateKey', 'DNS'], true)) {
                    $result[$key] = $value;
                }
                if ($section === 'interface' && $key === 'Address') {
                    // The IPv4 tunnel address; the IPv6 one is derived from it
                    $result['Address'] = IpAllocator::tunnelIp($value) ?? explode('/', $value, 2)[0];
                }
                if ($section === 'peer' && in_array($key, ['PresharedKey', 'AllowedIPs', 'PersistentKeepalive'], true)) {
                    $result[$key] = $value;
                }
            }
        }

        return $result;
    }
}
