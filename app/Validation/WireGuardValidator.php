<?php

namespace App\Validation;

use InvalidArgumentException;

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

    /**
     * @param  array  $existing_ips  List of existing peer IPs (with or without /32 suffix)
     */
    public function validateNewPeerIp(string $ip, string $interface_address, array $existing_ips): void
    {
        $this->validateIpAddress($ip);

        if (! $this->ipInRange($ip, $interface_address)) {
            throw new InvalidArgumentException(
                "Peer IP {$ip} is not within the interface's network range ({$interface_address})."
            );
        }

        foreach ($existing_ips as $existing) {
            $existing_clean = explode('/', $existing, 2)[0];
            if ($existing_clean === $ip) {
                throw new InvalidArgumentException("Peer with IP {$ip} already exists.");
            }
        }
    }
}
