<?php

namespace App\Services;

use App\DTOs\InterfaceInfo;
use App\DTOs\PeerInfo;
use App\Services\Os\OsDriver;

class ConfigBuilder
{
    /** Header of a disabled peer's section: the whole section is commented out. */
    public const DISABLED_PEER = '# [Peer] disabled';

    /**
     * What a client config gets unless its link or the peer says otherwise: all traffic through
     * the tunnel, a public resolver, and a keepalive that holds NAT mappings open. Fixed on
     * purpose: a default that could change would change what every stored client config means.
     */
    public const DEFAULT_DNS = '8.8.8.8';

    public const DEFAULT_KEEPALIVE = 25;

    public const DEFAULT_ALLOWED_IPS = '0.0.0.0/0';

    /**
     * Version of the link config format, written as `# format = …`. Since 2 a peer's own client
     * settings are stored in its section; before, they only showed in its client config.
     */
    public const FORMAT = 2;

    /** Seconds between the keepalives the server sends a peer it connects to itself (`remote`). */
    public const REMOTE_KEEPALIVE = 25;

    /** The client config when config('wireguard.templates.client') doesn't say otherwise. */
    public const CLIENT_TEMPLATE = "[Interface]\nPrivateKey = {privkey}\nAddress = {address}\nDNS = {dns}\nMTU = {mtu}\n\n[Peer]\nPublicKey = {pubkey}\nPresharedKey = {psk}\nAllowedIPs = {subnets}\nEndpoint = {endpoint}\nPersistentKeepalive = {keepalive}";

    /** What a peer's section holds as comments (peer field => comment key): its label and client settings. */
    public const PEER_SETTINGS = ['name' => 'name', 'dns' => 'dns', 'keepalive' => 'keepalive', 'client_allowed_ips' => 'allowed_ips'];

    /** This server's public address, once it had to be asked for (no WIREGUARD_HOSTNAME, no FQDN). */
    protected ?string $publicHost = null;

    public function __construct(
        protected array $config,
        protected OsDriver $os,
    ) {}

    public function buildConfFile(string $address, string $privkey, int $port, string $ifout, array $peers = [], ?string $dns = null, ?int $keepalive = null, ?string $allowed_ips = null, bool $forward = false, bool $nat = false, bool $up = true, ?string $address6 = null, ?int $mtu = null): string
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
        $lines[] = '# format = '.self::FORMAT;
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
        $lines[] = $this->os->interfaceSection($address6 === null ? $address : "{$address}, {$address6}", $privkey, $port, $ifout, $forward, $nat, $mtu);

        // Peer sections. A disabled peer is commented out, so wg-quick doesn't load it; its name
        // and its own client settings are comments either way.
        foreach ($peers as $peer) {
            $disabled = ($peer['enabled'] ?? true) === false;
            $prefix = $disabled ? '# ' : '';
            $lines[] = '';
            $lines[] = $disabled ? self::DISABLED_PEER : '[Peer]';
            foreach (self::PEER_SETTINGS as $field => $key) {
                if (($peer[$field] ?? null) !== null) {
                    $lines[] = "# {$key} = {$peer[$field]}";
                }
            }
            $lines[] = "{$prefix}PublicKey = {$peer['public_key']}";
            if (! empty($peer['preshared_key'])) {
                $lines[] = "{$prefix}PresharedKey = {$peer['preshared_key']}";
            }
            $lines[] = "{$prefix}AllowedIPs = {$peer['allowed_ips']}";
            // A peer the server connects to itself: it also has to keep trying, and keep the path open
            if (($peer['remote'] ?? null) !== null) {
                $lines[] = "{$prefix}Endpoint = {$peer['remote']}";
                $lines[] = "{$prefix}PersistentKeepalive = ".self::REMOTE_KEEPALIVE;
            }
        }

        return implode("\n", $lines);
    }

    /**
     * Client config values a link hands out unless a peer has its own: the link's metadata (dns,
     * keepalive, allowed_ips), else the fixed defaults.
     *
     * A dual-stack link without allowed_ips of its own sends all IPv6 traffic through the tunnel
     * too: ::/0 next to 0.0.0.0/0.
     *
     * @return array{dns: string, keepalive: string, allowed_ips: string}
     */
    public function clientDefaults(array $metadata): array
    {
        return [
            'dns' => (string) ($metadata['dns'] ?? self::DEFAULT_DNS),
            'keepalive' => (string) ($metadata['keepalive'] ?? self::DEFAULT_KEEPALIVE),
            'allowed_ips' => (string) ($metadata['allowed_ips'] ?? self::DEFAULT_ALLOWED_IPS.(isset($metadata['address6']) ? ', ::/0' : '')),
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

    /**
     * A peer's client config: its key and tunnel addresses, this server as its endpoint, and DNS,
     * routes and keepalive from the nearest place that has them: the peer, its link, the fixed
     * defaults. Null for a peer without an IPv4 tunnel address (not one of this app's).
     *
     * A template line whose value doesn't exist is left out (no MTU of the link's own, a peer
     * without a preshared key).
     */
    public function buildClientConfig(InterfaceInfo $link, PeerInfo $peer, string $privkey): ?string
    {
        $ip = IpAllocator::tunnelIp($peer->allowed_ips);
        if ($ip === null) {
            return null;
        }

        $settings = array_filter($peer->clientSettings(), fn ($value) => $value !== null)
            + $this->clientDefaults([...$link->clientSettings(), 'address6' => $link->address6]);

        // {address}: the Address value (both families); {ip}: the bare IPv4 tunnel address
        $values = [
            '{privkey}' => $privkey,
            '{pubkey}' => $link->public_key,
            '{psk}' => $peer->preshared_key ?: null,
            '{subnets}' => $settings['allowed_ips'],
            '{keepalive}' => (string) $settings['keepalive'],
            '{dns}' => $settings['dns'],
            '{endpoint}' => $this->endpoint($link),
            '{address}' => $this->clientAddress($link, $ip),
            '{ip}' => $ip,
            '{mtu}' => $link->mtu === null ? null : (string) $link->mtu,
        ];
        $lines = array_filter(
            explode("\n", $this->config['templates']['client'] ?? self::CLIENT_TEMPLATE),
            fn (string $line) => ! array_any($values, fn (?string $value, string $placeholder) => $value === null && str_contains($line, $placeholder)),
        );

        return strtr(implode("\n", $lines), array_filter($values, fn (?string $value) => $value !== null));
    }

    /**
     * Where clients reach this link: WIREGUARD_HOSTNAME, else the machine's name when that looks
     * reachable (an FQDN or IP), else its public IPv4.
     */
    protected function endpoint(InterfaceInfo $link): string
    {
        $host = $this->config['hostname'] ?? null;
        if ($host === null || $host === '') {
            $hostname = gethostname();
            // Looked up once per process: client configs are built on every read
            $host = filter_var($hostname, FILTER_VALIDATE_IP) || str_contains($hostname, '.')
                ? $hostname
                : ($this->publicHost ??= $this->os->publicIpv4($this->config['ip_service'] ?? 'http://ifconfig.me/ip') ?? $hostname);
        }

        // An IPv6 literal needs brackets before the port
        return filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) ? "[{$host}]:{$link->listen_port}" : "{$host}:{$link->listen_port}";
    }

    /**
     * What is stored for a peer: only what can't be derived, its private key. Its client config is
     * built from it whenever it is asked for.
     */
    public static function clientKeyFile(string $privkey): string
    {
        return "# This peer's private key. Its client config is built from it and the link's settings.\nPrivateKey = {$privkey}";
    }

    /**
     * The private key in a peer's stored file: a key file, or a whole client config as stored
     * before client configs were built on demand.
     */
    public static function clientPrivateKey(?string $content): ?string
    {
        return preg_match('/^\s*PrivateKey\s*=\s*(\S+)\s*$/m', (string) $content, $m) && KeyManager::isKey($m[1]) ? $m[1] : null;
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

            // A disabled peer: its section is commented out
            if ($trimmed === self::DISABLED_PEER) {
                $current_section = 'disabled';
                $peers[] = ['disabled' => true];

                continue;
            }
            // A peer's label and own client settings, comments in a live section too
            if (in_array($current_section, ['peer', 'disabled'], true) && preg_match('/^#\s*(name|dns|keepalive|allowed_ips)\s*=\s*(.+)$/', $trimmed, $matches)) {
                $peers[count($peers) - 1][array_search($matches[1], self::PEER_SETTINGS, true)] = trim($matches[2]);

                continue;
            }
            if ($current_section === 'disabled' && preg_match('/^#\s*(PublicKey|PresharedKey|AllowedIPs|Endpoint|PersistentKeepalive)\s*=\s*(.+)$/', $trimmed, $matches)) {
                $peers[count($peers) - 1][$matches[1]] = trim($matches[2]);

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

    /**
     * Lines of $content that $rebuilt, the same config regenerated by the app, no longer has:
     * settings and comments the app doesn't write (MTU, Table, other hooks, a peer's Endpoint, …),
     * which a rewrite would drop. Spacing around `=` doesn't count, and neither do the helper's
     * own hooks: those are written anew for this server.
     *
     * @return list<string>
     */
    public static function droppedLines(string $content, string $rebuilt): array
    {
        $lines = fn (string $text): array => array_filter(
            array_map(fn (string $line) => preg_replace('/^([A-Za-z0-9]+)\s*=\s*/', '$1 = ', trim($line)), explode("\n", $text)),
            fn (string $line) => $line !== '' && ! preg_match('#^Post(Up|Down) = \S*wgla-helper firewall-(up|down)( %[iI])+$#', $line),
        );

        $kept = array_count_values($lines($rebuilt));
        $dropped = [];
        foreach ($lines($content) as $line) {
            if (($kept[$line] ?? 0) > 0) {
                $kept[$line]--;
            } else {
                $dropped[] = $line;
            }
        }

        return $dropped;
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
