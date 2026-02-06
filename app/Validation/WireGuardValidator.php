<?php

namespace App\Validation;

use InvalidArgumentException;

class WireGuardValidator
{
    /**
     * Check if an IP is within a CIDR range.
     */
    public function ipInRange(string $ip, string $range): bool
    {
        if (! str_contains($range, '/')) {
            $range .= '/32';
        }

        [$network, $netmask] = explode('/', $range, 2);
        $netmask = (int) $netmask;
        $rangeDec = ip2long($network);
        $ipDec = ip2long($ip);
        $wildcardDec = pow(2, 32 - $netmask) - 1;
        $netmaskDec = ~$wildcardDec;

        return ($ipDec & $netmaskDec) === ($rangeDec & $netmaskDec);
    }

    /**
     * Validate an interface name (alphanumeric + hyphens, max 15 chars).
     */
    public function validateInterfaceName(string $name): void
    {
        if (! preg_match('/^[a-zA-Z][a-zA-Z0-9_-]{0,14}$/', $name)) {
            throw new InvalidArgumentException(
                'Interface name must start with a letter, contain only alphanumeric/hyphen/underscore characters, and be at most 15 characters.'
            );
        }
    }

    /**
     * Validate an IPv4 address.
     */
    public function validateIpAddress(string $ip): void
    {
        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new InvalidArgumentException("Invalid IPv4 address: {$ip}");
        }
    }

    /**
     * Validate an IPv4 address with CIDR notation.
     */
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

    /**
     * Validate a port number.
     */
    public function validatePort(int $port): void
    {
        if ($port < 1 || $port > 65535) {
            throw new InvalidArgumentException("Invalid port number: {$port}");
        }
    }

    /**
     * Ensure a peer IP is within the interface's address range and is not a duplicate.
     *
     * @param  array  $existingIps  List of existing peer IPs (with or without /32 suffix)
     */
    public function validateNewPeerIp(string $ip, string $interfaceAddress, array $existingIps): void
    {
        $this->validateIpAddress($ip);

        if (! $this->ipInRange($ip, $interfaceAddress)) {
            throw new InvalidArgumentException(
                "Peer IP {$ip} is not within the interface's network range ({$interfaceAddress})."
            );
        }

        foreach ($existingIps as $existing) {
            $existingClean = str_replace('/32', '', $existing);
            if ($existingClean === $ip) {
                throw new InvalidArgumentException("Peer with IP {$ip} already exists.");
            }
        }
    }
}
