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
     * Get the public IP address via an external service.
     */
    public function publicIp(string $ip_service): string;

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
     * Create a network device and return the OS-level interface name.
     */
    public function createInterface(string $name): string;

    /**
     * Remove a network device.
     */
    public function destroyInterface(string $ifname): void;

    /**
     * Assign an IP address with CIDR to an interface.
     */
    public function assignAddress(string $ifname, string $address): void;

    /**
     * Bring the interface up.
     */
    public function bringUp(string $ifname): void;

    /**
     * Add per-interface NAT/forwarding rules.
     */
    public function addNatRules(string $ifname, string $address, string $ifout): void;

    /**
     * Remove per-interface NAT/forwarding rules.
     */
    public function removeNatRules(string $ifname): void;

    /**
     * Check if IP forwarding is currently enabled.
     */
    public function isForwardingEnabled(): bool;

    /**
     * Enable IP forwarding.
     */
    public function enableForwarding(): void;

    /**
     * Disable IP forwarding.
     */
    public function disableForwarding(): void;
}
