<?php

namespace App\Validation;

use App\Services\IpAllocator;
use InvalidArgumentException;

/**
 * Everything user-supplied that ends up in a wg-quick config (run by root) or a client config is
 * checked against a strict format here, so no value can inject extra lines into those files.
 */
class WireGuardValidator
{
    public function ipInRange(string $ip, string $range): bool
    {
        if (! str_contains($range, '/')) {
            $range .= '/32';
        }

        [$network, $netmask] = explode('/', $range, 2);
        $netmask = (int) $netmask;
        $range_dec = ip2long($network);
        $ip_dec = ip2long($ip);
        $wildcard_dec = pow(2, 32 - $netmask) - 1;
        $netmask_dec = ~$wildcard_dec;

        return ($ip_dec & $netmask_dec) === ($range_dec & $netmask_dec);
    }

    public function validateInterfaceName(string $name): void
    {
        if (! preg_match('/^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/', $name)) {
            throw new InvalidArgumentException(
                'Interface name must start with a letter, contain only alphanumeric/hyphen/underscore characters, and be at most 15 characters.'
            );
        }
    }

    /**
     * Name format of an outbound interface (existence is checked against the OS separately).
     */
    public function validateOutboundInterface(string $name): void
    {
        if (! preg_match('/^[A-Za-z0-9_.-]{1,15}$/', $name)) {
            throw new InvalidArgumentException("Invalid outbound interface name: {$name}");
        }
    }

    public function validateIpAddress(string $ip): void
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new InvalidArgumentException("Invalid IPv4 address: {$ip}");
        }
    }

    /**
     * An IPv4 address with its mask. Returns it with the mask as a plain number (/08 → /8).
     */
    public function validateCidr(string $cidr): string
    {
        if (! preg_match('#^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$#', $cidr)) {
            throw new InvalidArgumentException("Invalid CIDR notation: {$cidr}");
        }

        [$ip, $mask] = explode('/', $cidr, 2);
        $this->validateIpAddress($ip);

        if ((int) $mask < 0 || (int) $mask > 32) {
            throw new InvalidArgumentException("Invalid CIDR mask: {$mask}");
        }

        return $ip.'/'.(int) $mask;
    }

    /**
     * A new address for a link (10.0.0.1/24), returned like validateCidr() does. It must be a
     * host inside a subnet of its own: a /0 would route everything into the tunnel, and an
     * interface can't have its subnet's network or broadcast address.
     */
    public function linkAddress(string $cidr): string
    {
        $cidr = $this->validateCidr($cidr);
        [$ip, $mask] = explode('/', $cidr, 2);
        $mask = (int) $mask;

        if ($mask === 0) {
            throw new InvalidArgumentException("{$cidr} covers every address; a link needs a subnet of its own (e.g. {$ip}/24).");
        }
        if ($mask <= 30) {
            $network = ip2long($ip) & ((-1 << (32 - $mask)) & 0xFFFFFFFF);
            $broadcast = $network | ((1 << (32 - $mask)) - 1);
            if (in_array(ip2long($ip), [$network, $broadcast], true)) {
                throw new InvalidArgumentException("{$ip} is the network or broadcast address of {$cidr}; give the link a host address in it (e.g. ".long2ip($network + 1)."/{$mask}).");
            }
        }

        return $cidr;
    }

    /**
     * A link's IPv6 address and prefix (fd12:3456:789a::1/64), next to its IPv4 $address. Returns
     * it in canonical form. It must be unique local (fc00::/7) or global unicast (2000::/3), not
     * the prefix itself, and leave room for every IPv4 host number (peers mirror theirs into it).
     */
    public function address6(string $cidr, string $address): string
    {
        if (! preg_match('#^([0-9A-Fa-f:]+)/(\d{1,3})$#', $cidr, $m) || ! filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            throw new InvalidArgumentException("Invalid IPv6 address with prefix (e.g. fd12:3456:789a::1/64): {$cidr}");
        }

        $prefix = (int) $m[2];
        $ip = inet_ntop(inet_pton($m[1]));
        if ($prefix < 1 || $prefix > 126) {
            throw new InvalidArgumentException("Invalid IPv6 prefix length: /{$prefix}");
        }
        if (! IpAllocator::overlaps($ip, 'fc00::/7') && ! IpAllocator::overlaps($ip, '2000::/3')) {
            throw new InvalidArgumentException("{$ip} is neither a unique local (fc00::/7) nor a global unicast (2000::/3) address");
        }
        if (IpAllocator::networkCidr("{$ip}/{$prefix}") === "{$ip}/{$prefix}") {
            throw new InvalidArgumentException("{$ip}/{$prefix} is the prefix itself; give the link an address in it (e.g. ::1)");
        }

        $v4_host_bits = 32 - (int) (explode('/', $address, 2)[1] ?? 32);
        if (128 - $prefix < $v4_host_bits) {
            throw new InvalidArgumentException("IPv6 prefix /{$prefix} is too small for {$address}: peers mirror their IPv4 host number into it");
        }

        return "{$ip}/{$prefix}";
    }

    /**
     * A peer's label: 1-64 characters, any script, no control characters. Returns it trimmed.
     */
    public function peerName(string $name): string
    {
        $name = trim($name);
        if ($name === '' || ! mb_check_encoding($name, 'UTF-8') || mb_strlen($name) > 64 || preg_match('/\p{Cc}/u', $name)) {
            throw new InvalidArgumentException('A peer name must be 1-64 characters, without line breaks or control characters.');
        }

        return $name;
    }

    /**
     * Networks behind a peer (site-to-site), as a comma-separated list of CIDRs of either family.
     * Returns them as network addresses (192.168.1.5/24 → 192.168.1.0/24, which is what wg reports),
     * without duplicates. A default route would send all of the server's traffic to the peer.
     *
     * @return list<string>
     */
    public function networks(string $networks): array
    {
        $this->validateAllowedIps($networks);

        $reserved = ['127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '::1/128', 'fe80::/10', 'ff00::/8'];
        $result = [];
        foreach ($this->entries($networks) as $entry) {
            $network = IpAllocator::networkCidr($entry);
            if (str_ends_with($network, '/0')) {
                throw new InvalidArgumentException("{$entry} is a default route: it would send all of the server's traffic to the peer.");
            }
            foreach ($reserved as $range) {
                if (IpAllocator::overlaps($network, $range)) {
                    throw new InvalidArgumentException("{$entry} overlaps reserved addresses ({$range}).");
                }
            }
            $result[] = $network;
        }

        return array_values(array_unique($result));
    }

    public function validatePort(int $port): void
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException("Invalid port number: {$port}");
        }
    }

    public function validateKeepalive(int $seconds): void
    {
        if ($seconds < 0 || $seconds > 65535) {
            throw new InvalidArgumentException("Invalid keepalive interval: {$seconds}");
        }
    }

    /**
     * Comma-separated DNS servers and search domains, as the wg-quick DNS key takes them.
     * Returns the list as it is written into configs: `a, b` (which is all the root helper takes).
     */
    public function validateDns(string $dns): string
    {
        foreach ($entries = $this->entries($dns) as $entry) {
            if (! filter_var($entry, FILTER_VALIDATE_IP) && ! $this->isHostname($entry)) {
                throw new InvalidArgumentException("Invalid DNS server or search domain: {$entry}");
            }
        }

        return implode(', ', $entries);
    }

    /**
     * Comma-separated IPv4/IPv6 addresses or CIDRs, as in an AllowedIPs line. Returns the list
     * as it is written into configs: `a, b`.
     */
    public function validateAllowedIps(string $allowed_ips): string
    {
        foreach ($entries = $this->entries($allowed_ips) as $entry) {
            [$ip, $mask] = array_pad(explode('/', $entry, 2), 2, null);

            $max = match (true) {
                (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) => 32,
                (bool) filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) => 128,
                default => null,
            };

            if ($max === null || ($mask !== null && (! ctype_digit($mask) || (int) $mask > $max))) {
                throw new InvalidArgumentException("Invalid allowed IP or CIDR: {$entry}");
            }
        }

        return implode(', ', $entries);
    }

    /**
     * A peer gets exactly one tunnel address: `10.0.0.2` or `10.0.0.2/32`. Returns the bare IP.
     */
    public function peerAddress(string $ip): string
    {
        [$bare, $mask] = array_pad(explode('/', $ip, 2), 2, '32');

        if ($mask !== '32') {
            throw new InvalidArgumentException("A peer address must be a single IP (/32), got: {$ip}");
        }

        $this->validateIpAddress($bare);

        return $bare;
    }

    /**
     * @param  array  $existing_ips  AllowedIPs of the other peers (their tunnel address comes first)
     * @param  string|null  $address6  the link's IPv6 address: a peer can't mirror onto it
     */
    public function validateNewPeerIp(string $ip, string $interface_address, array $existing_ips, ?string $address6 = null): void
    {
        $this->validateIpAddress($ip);

        if (! $this->ipInRange($ip, $interface_address)) {
            throw new InvalidArgumentException(
                "Peer IP {$ip} is not within the interface's network range ({$interface_address})."
            );
        }

        [$link_ip, $mask] = array_pad(explode('/', $interface_address, 2), 2, '32');
        if ($ip === $link_ip) {
            throw new InvalidArgumentException("Peer IP {$ip} is the link's own address.");
        }

        $host_bits = 32 - (int) $mask;
        $network = ip2long($link_ip) & ((-1 << $host_bits) & 0xFFFFFFFF);
        $broadcast = $network | ((1 << $host_bits) - 1);
        if ($host_bits >= 2 && in_array(ip2long($ip), [$network, $broadcast], true)) {
            throw new InvalidArgumentException("Peer IP {$ip} is the network or broadcast address of {$interface_address}.");
        }

        foreach ($existing_ips as $existing) {
            if (IpAllocator::tunnelIp($existing) === $ip) {
                throw new InvalidArgumentException("Peer with IP {$ip} already exists.");
            }
        }

        if ($address6 !== null) {
            [$link_ip6] = explode('/', $address6, 2);
            if (IpAllocator::mirror($ip, $interface_address, $address6) === $link_ip6) {
                throw new InvalidArgumentException("Peer IP {$ip} would get the link's own IPv6 address ({$link_ip6}).");
            }
        }
    }

    /**
     * Split a comma-separated list, rejecting control characters (newlines would start new
     * config lines) and empty entries.
     *
     * @return list<string>
     */
    protected function entries(string $value): array
    {
        if (preg_match('/[\x00-\x1F\x7F]/', $value)) {
            throw new InvalidArgumentException('Value must not contain control characters or line breaks.');
        }

        $entries = array_map('trim', explode(',', $value));
        if (in_array('', $entries, true)) {
            throw new InvalidArgumentException("Empty entry in list: {$value}");
        }

        return $entries;
    }

    protected function isHostname(string $name): bool
    {
        return strlen($name) <= 253
            && (bool) preg_match('/^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/', $name);
    }
}
