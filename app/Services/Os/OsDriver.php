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
    public function publicIp(string $ipService): string;

    /**
     * Get list of network interface names.
     */
    public function networkInterfaces(): array;

    /**
     * Get the VPN address assigned to a WireGuard interface.
     */
    public function interfaceAddress(string $ifname): ?string;

    /**
     * Get the WireGuard config directory path.
     */
    public function configPath(): string;

    /**
     * Generate the interface config file content.
     */
    public function interfaceTemplate(string $address, string $privkey, int $port, string $ifout): string;

    /**
     * Start a WireGuard interface (bring it up + enable on boot).
     */
    public function startInterface(string $name): void;

    /**
     * Stop a WireGuard interface (bring it down + disable on boot).
     */
    public function stopInterface(string $name): void;
}
