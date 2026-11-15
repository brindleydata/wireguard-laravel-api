<?php

namespace App\Services;

use App\Exceptions\ConflictException;
use InvalidArgumentException;
use RuntimeException;

/**
 * Address math for both families. A link has an IPv4 subnet and optionally an IPv6 prefix; a
 * peer's IPv6 tunnel address mirrors its IPv4 host number inside that prefix (10.0.0.5 in
 * 10.0.0.0/24 → fd12:3456:789a::5 in fd12:3456:789a::/64), so a peer only has one address to
 * allocate and move.
 */
class IpAllocator
{
    /**
     * Network of a CIDR, either family: 10.0.0.1/24 → 10.0.0.0/24, fd12::1/64 → fd12::/64.
     * A bare IP is a host route (/32 or /128).
     */
    public static function networkCidr(string $cidr): string
    {
        [$bytes, $mask] = self::parse($cidr);

        return inet_ntop(self::masked($bytes, $mask))."/{$mask}";
    }

    /**
     * Whether two CIDRs share any address. CIDRs of different families never do.
     */
    public static function overlaps(string $a, string $b): bool
    {
        [$a_bytes, $a_mask] = self::parse($a);
        [$b_bytes, $b_mask] = self::parse($b);
        if (strlen($a_bytes) !== strlen($b_bytes)) {
            return false;
        }
        $mask = min($a_mask, $b_mask);

        return self::masked($a_bytes, $mask) === self::masked($b_bytes, $mask);
    }

    /**
     * Host number of an address inside a CIDR's network (10.0.0.5 in 10.0.0.0/24 → 5), or null
     * when it's outside the network or the number doesn't fit an int.
     */
    public static function hostIndex(string $ip, string $cidr): ?int
    {
        [$bytes] = self::parse($ip);
        [$net_bytes, $mask] = self::parse($cidr);
        if (strlen($bytes) !== strlen($net_bytes) || self::masked($bytes, $mask) !== self::masked($net_bytes, $mask)) {
            return null;
        }

        $host = $bytes ^ self::masked($bytes, $mask);
        $high = substr($host, 0, -8);
        if (trim($high, "\0") !== '') {
            return null;
        }
        $index = unpack('J', str_pad(substr($host, -8), 8, "\0", STR_PAD_LEFT))[1];

        return $index >= 0 ? $index : null;
    }

    /**
     * The address with a host number inside a CIDR's network (fd12::/64, 5 → fd12::5).
     */
    public static function hostAt(string $cidr, int $index): string
    {
        [$bytes, $mask] = self::parse($cidr);
        $host_bits = strlen($bytes) * 8 - $mask;
        if ($index < 0 || ($host_bits < 63 && $index >= (1 << $host_bits))) {
            throw new InvalidArgumentException("Host number {$index} doesn't fit {$cidr}");
        }

        $network = self::masked($bytes, $mask);
        $width = min(8, strlen($network));
        $tail = substr(pack('J', $index), -$width);

        return inet_ntop(substr($network, 0, -$width).(substr($network, -$width) | $tail));
    }

    /**
     * A peer's IPv6 tunnel address: its IPv4 host number inside the link's IPv6 prefix.
     */
    public static function mirror(string $peer_ip, string $address, string $address6): string
    {
        $index = self::hostIndex($peer_ip, $address)
            ?? throw new InvalidArgumentException("{$peer_ip} is not inside {$address}");

        return self::hostAt($address6, $index);
    }

    /**
     * Server-side AllowedIPs of a peer: its IPv4 /32, plus the mirrored IPv6 /128 on a dual-stack link.
     */
    public static function peerAllowedIps(string $ip, string $address, ?string $address6): string
    {
        return $address6 === null ? "{$ip}/32" : "{$ip}/32, ".self::mirror($ip, $address, $address6).'/128';
    }

    /**
     * A peer's IPv4 tunnel address: the first IPv4 entry of its AllowedIPs, without the mask.
     */
    public static function tunnelIp(?string $allowed_ips): ?string
    {
        foreach (explode(',', (string) $allowed_ips) as $entry) {
            $ip = explode('/', trim($entry), 2)[0];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
                return $ip;
            }
        }

        return null;
    }

    /**
     * Networks behind a peer: its AllowedIPs besides its tunnel addresses (the IPv4 /32 and, on a
     * dual-stack link, the /128 in the link's prefix).
     *
     * @return list<string>
     */
    public static function networksOf(?string $allowed_ips, ?string $address6): array
    {
        $ip = self::tunnelIp($allowed_ips);

        return array_values(array_filter(
            array_map('trim', explode(',', (string) $allowed_ips)),
            fn (string $entry) => $entry !== '' && $entry !== "{$ip}/32"
                && ! ($address6 !== null && str_ends_with($entry, '/128') && self::overlaps($entry, $address6)),
        ));
    }

    /**
     * A random RFC 4193 unique local /64 (fd + 40 random bits + subnet 0), e.g. fd3c:91a2:5e07::/64.
     */
    public static function randomUlaPrefix(): string
    {
        return inet_ntop("\xfd".random_bytes(5).str_repeat("\0", 10)).'/64';
    }

    /**
     * @param  string|null  $address6  the link's IPv6 address: the host number it uses is skipped,
     *                                 so no peer mirrors onto it
     */
    public function findAvailableIp(string $interface_address, array $existing_peers, ?string $address6 = null): string
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

        if ($address6 !== null && ($index = self::hostIndex(explode('/', $address6, 2)[0], $address6)) !== null) {
            $used[$network_start + $index] = true;
        }

        foreach ($existing_peers as $peer) {
            if (($peer_ip = self::tunnelIp($peer->allowed_ips)) !== null) {
                $used[ip2long($peer_ip)] = true;
            }
        }

        // Find first available host
        for ($ip = $network_start + 1; $ip < $network_end; $ip++) {
            if (! isset($used[$ip])) {
                return long2ip($ip);
            }
        }

        throw new ConflictException('No available IP addresses in subnet.');
    }

    /**
     * @return array{0: string, 1: int} packed address, prefix length
     */
    protected static function parse(string $cidr): array
    {
        [$ip, $mask] = array_pad(explode('/', trim($cidr), 2), 2, null);
        $bytes = @inet_pton($ip);
        if ($bytes === false) {
            throw new InvalidArgumentException("Invalid IP address: {$ip}");
        }

        return [$bytes, $mask === null ? strlen($bytes) * 8 : (int) $mask];
    }

    protected static function masked(string $bytes, int $mask): string
    {
        $out = '';
        foreach (str_split($bytes) as $i => $byte) {
            $bits = max(0, min(8, $mask - $i * 8));
            $out .= chr(ord($byte) & ((0xFF << (8 - $bits)) & 0xFF));
        }

        return $out;
    }
}
