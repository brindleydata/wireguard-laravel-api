<?php

namespace App\Services\Os;

interface OsDriver
{
    /**
     * Get CPU info: cores, load, usage percentage.
     */
    public function cpu(): array;

    /**
     * Get RAM info: total, free (in kB), usage percentage.
     */
    public function ram(): array;

    /**
     * Get disk info: partition, size, free, usage percentage.
     */
    public function disk(string $partition = '/'): array;

    /**
     * Get the public IPv4 address via an external service.
     */
    public function publicIpv4(string $ip_service): ?string;

    /**
     * Get the public IPv6 address via an external service.
     */
    public function publicIpv6(string $ip_service): ?string;

    /**
     * Get list of network interface names.
     */
    public function networkInterfaces(): array;

    /**
     * Get the VPN address assigned to a WireGuard interface.
     */
    public function interfaceAddress(string $ifname): ?string;

    /**
     * Get the default outbound network interface (from the default route).
     */
    public function defaultOutboundInterface(): string;

    /**
     * Get the OS-specific wg-quick config directory path.
     */
    public function configPath(): string;

    /**
     * Generate the [Interface] section for a wg-quick config, including PostUp/PostDown NAT hooks.
     */
    public function interfaceSection(string $address, string $privkey, int $port, string $ifout): string;

    /**
     * Write a wg-quick .conf file securely (chmod 0600).
     */
    public function writeConfig(string $name, string $content): void;

    /**
     * Delete a wg-quick .conf file.
     */
    public function deleteConfig(string $name): void;

    /**
     * Read a wg-quick .conf file, or null if it doesn't exist.
     */
    public function readConfig(string $name): ?string;

    /**
     * Check if a wg-quick .conf file exists.
     */
    public function configExists(string $name): bool;

    /**
     * Parse metadata from comment headers in a wg-quick .conf file.
     * Returns array with keys: address, ifout, and optionally dns, keepalive, allowed_ips.
     * Returns null if the config file doesn't exist.
     */
    public function parseConfig(string $name): ?array;

    /**
     * Bring up a WireGuard interface via wg-quick or systemctl.
     */
    public function startInterface(string $name): void;

    /**
     * Bring down a WireGuard interface via wg-quick or systemctl.
     */
    public function stopInterface(string $name): void;

    /**
     * Write a client (peer) config file.
     */
    public function writeClientConfig(string $link, string $ip, string $content): void;

    /**
     * Read a client (peer) config file, or null if it doesn't exist.
     */
    public function readClientConfig(string $link, string $ip): ?string;

    /**
     * Delete a client (peer) config file.
     */
    public function deleteClientConfig(string $link, string $ip): void;

    /**
     * Delete the entire client config directory for a link.
     */
    public function deleteClientConfigDir(string $link): void;
}
