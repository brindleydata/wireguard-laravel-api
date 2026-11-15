<?php

namespace App\Services\Os;

/**
 * Host operations. System information is read directly; everything privileged goes through the
 * root helper (bin/wgla-helper), which validates every argument and config it is given.
 */
interface OsDriver
{
    // ─── System information ─────────────────────────────────────────

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
     * The addresses the server needs to stay reachable itself, of either family: those of its
     * interfaces, and its default gateway. No route to a peer may cover them.
     *
     * @return list<string>
     */
    public function ownAddresses(): array;

    // ─── Root helper ────────────────────────────────────────────────

    /**
     * Whether the installed root helper is usable: `ok`, `missing`, `outdated` (it differs from
     * the bin/wgla-helper this app ships) or `not-allowed` (sudoers doesn't let us run it).
     * Never throws.
     *
     * @return array{state: string, installed: ?string, bundled: ?string} versions of both copies
     */
    public function helperStatus(): array;

    // ─── WireGuard runtime state ────────────────────────────────────

    /**
     * Names of the running WireGuard interfaces (`wg show interfaces`). Throws
     * CommandFailedException when they can't be read: an empty list would say every link is down.
     */
    public function runningInterfaces(): array;

    /**
     * `wg show <iface> dump`. Throws CommandFailedException when it can't be read.
     */
    public function interfaceDump(string $iface): string;

    /**
     * Add peers to a running interface from [Peer] sections (`wg addconf`).
     */
    public function addPeer(string $iface, string $section): void;

    public function removePeer(string $iface, string $pubkey): void;

    public function setPeerAllowedIps(string $iface, string $pubkey, string $allowed_ips): void;

    // ─── Link lifecycle ─────────────────────────────────────────────

    /**
     * Map a link name to the OS interface wg-quick created for it.
     *
     * Linux: the link name itself. macOS: wg-quick always creates a fresh utunN and records it in
     * /var/run/wireguard/<link>.name; falls back to the link name when there is no mapping.
     * The caller must still check runningInterfaces() to know whether it is running.
     * Throws CommandFailedException when the helper can't be asked.
     */
    public function resolveInterface(string $link): string;

    /**
     * Bring a link up (Linux: enable + start its wg-quick@ unit; macOS: wg-quick up).
     */
    public function startInterface(string $name): void;

    /**
     * Bring a link down. Idempotent; on Linux it also disables the unit of a stopped link.
     */
    public function stopInterface(string $name): void;

    // ─── Link configs ───────────────────────────────────────────────

    /**
     * The [Interface] section of a wg-quick config. With forward or NAT on, its PostUp/PostDown
     * hooks call the helper's firewall commands (the only hooks the helper accepts).
     */
    public function interfaceSection(string $address, string $privkey, int $port, string $ifout, bool $forward = false, bool $nat = false, ?int $mtu = null): string;

    /**
     * Write a wg-quick .conf (0600). The helper rejects anything the app wouldn't generate.
     */
    public function writeConfig(string $name, string $content): void;

    /**
     * Delete a link's .conf (nothing to do when there is none). Throws CommandFailedException
     * when it couldn't be deleted: the link would still be there.
     */
    public function deleteConfig(string $name): void;

    /**
     * Read a wg-quick .conf, or null if it doesn't exist. Throws CommandFailedException when it
     * can't be read for any other reason.
     */
    public function readConfig(string $name): ?string;

    public function configExists(string $name): bool;

    /**
     * Names of all links that have a .conf. Throws CommandFailedException when they can't be listed.
     */
    public function listConfigNames(): array;

    // ─── Client configs ─────────────────────────────────────────────

    public function writeClientConfig(string $link, string $key, string $content): void;

    /**
     * A peer's stored client config, or null if there is none. Throws like readConfig().
     */
    public function readClientConfig(string $link, string $key): ?string;

    /**
     * Delete what is stored for a peer (its private key), or for every peer of a link. Nothing to
     * do when there is nothing; both throw CommandFailedException when it couldn't be deleted.
     */
    public function deleteClientConfig(string $link, string $key): void;

    public function deleteClientConfigDir(string $link): void;

    // ─── Firewall ───────────────────────────────────────────────────

    /**
     * Install the forward/NAT rules saved in the link's config for its running interface
     * (clearing them when both are off). The PostUp hook does the same.
     */
    public function applyFirewall(string $link, string $iface): void;

    /**
     * Whether a running link still has the forward/NAT rules its config asks for. Another tool
     * can take them away (a ruleset reload that flushes everything, a firewall restart).
     */
    public function firewallIntact(string $link, string $iface): bool;

    /**
     * Remove a link's forward/NAT rules. Never throws.
     */
    public function clearFirewall(string $link): void;
}
