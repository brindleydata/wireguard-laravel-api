<?php

namespace App\DTOs;

class PeerInfo
{
    /** WireGuard re-handshakes every 2 minutes while traffic flows, and drops a session after 3. */
    public const CONNECTED_WITHIN = 180;

    /**
     * The stats come from the running interface (`wg show dump`); they are null while the link is
     * down, and for a disabled peer (which is not on the interface).
     *
     * @param  int|null  $latest_handshake  Unix time; null when it never happened
     * @param  string|null  $networks  networks behind the peer (site-to-site): its server-side
     *                                 AllowedIPs besides its tunnel addresses
     */
    public function __construct(
        public readonly string $public_key,
        public readonly ?string $preshared_key = null,
        public readonly ?string $allowed_ips = null,
        public readonly ?string $private_key = null,
        public readonly ?string $client_config = null,
        public readonly ?string $endpoint = null,
        public readonly ?int $latest_handshake = null,
        public readonly ?int $transfer_rx = null,
        public readonly ?int $transfer_tx = null,
        public readonly ?string $name = null,
        public readonly bool $enabled = true,
        public readonly ?string $networks = null,
    ) {}

    /** Null while the link is down: there is nothing to know. */
    public function connected(?int $now = null): ?bool
    {
        if ($this->transfer_rx === null) {
            return null;
        }

        return $this->latest_handshake !== null && ($now ?? time()) - $this->latest_handshake < self::CONNECTED_WITHIN;
    }

    public function toArray(): array
    {
        $data = [
            'public_key' => $this->public_key,
            'name' => $this->name,
            'enabled' => $this->enabled,
            'preshared_key' => $this->preshared_key,
            'allowed_ips' => $this->allowed_ips,
            'networks' => $this->networks,
            'endpoint' => $this->endpoint,
            'latest_handshake_at' => $this->latest_handshake === null ? null : gmdate('Y-m-d\TH:i:s\Z', $this->latest_handshake),
            'connected' => $this->connected(),
            'transfer_rx' => $this->transfer_rx,
            'transfer_tx' => $this->transfer_tx,
        ];

        if ($this->private_key !== null) {
            $data['private_key'] = $this->private_key;
        }

        if ($this->client_config !== null) {
            $data['client_config'] = $this->client_config;
        }

        return $data;
    }
}
