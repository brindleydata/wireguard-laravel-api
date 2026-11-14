<?php

namespace App\Validation;

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

    public function validateCidr(string $cidr): void
    {
        if (! preg_match('#^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$#', $cidr)) {
            throw new InvalidArgumentException("Invalid CIDR notation: {$cidr}");
        }

        [$ip, $mask] = explode('/', $cidr, 2);
        $this->validateIpAddress($ip);

        if ((int) $mask < 0 || (int) $mask > 32) {
            throw new InvalidArgumentException("Invalid CIDR mask: {$mask}");
        }
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
     */
    public function validateDns(string $dns): void
    {
        foreach ($this->entries($dns) as $entry) {
            if (! filter_var($entry, FILTER_VALIDATE_IP) && ! $this->isHostname($entry)) {
                throw new InvalidArgumentException("Invalid DNS server or search domain: {$entry}");
            }
        }
    }

    /**
     * Comma-separated IPv4/IPv6 addresses or CIDRs, as in an AllowedIPs line.
     */
    public function validateAllowedIps(string $allowed_ips): void
    {
        foreach ($this->entries($allowed_ips) as $entry) {
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
     * @param  array  $existing_ips  Tunnel addresses of the other peers (with or without /32 suffix)
     */
    public function validateNewPeerIp(string $ip, string $interface_address, array $existing_ips): void
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
            $existing_clean = explode('/', $existing, 2)[0];
            if ($existing_clean === $ip) {
                throw new InvalidArgumentException("Peer with IP {$ip} already exists.");
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
