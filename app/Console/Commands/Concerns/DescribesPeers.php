<?php

namespace App\Console\Commands\Concerns;

use App\DTOs\PeerInfo;

/**
 * A peer in words: whether it is connected, and what it has besides its keys.
 */
trait DescribesPeers
{
    protected function state(PeerInfo $peer): string
    {
        if (! $peer->enabled) {
            return 'disabled';
        }

        return match ($peer->connected()) {
            null => '(link down)',
            false => $peer->latest_handshake === null ? 'never connected' : 'last seen '.$this->ago($peer->latest_handshake),
            true => sprintf('connected from %s, %s; ↓%s ↑%s', $peer->endpoint, $this->ago($peer->latest_handshake),
                $this->bytes($peer->transfer_rx), $this->bytes($peer->transfer_tx)),
        };
    }

    /**
     * What the peer has besides its keys and address, one line each.
     *
     * @return list<string>
     */
    protected function details(PeerInfo $peer): array
    {
        $own = array_filter($peer->clientSettings(), fn ($value) => $value !== null);

        return array_values(array_filter([
            "Allowed IPs: {$peer->allowed_ips}",
            $peer->networks === null ? null : "Networks behind it: {$peer->networks}",
            $peer->remote === null ? null : "Remote: {$peer->remote}",
            $own === [] ? null : 'Own client settings: '.implode(', ', array_map(fn ($value, string $key) => "{$key} {$value}", $own, array_keys($own))),
        ]));
    }

    protected function ago(int $time): string
    {
        $seconds = max(0, time() - $time);

        return match (true) {
            $seconds < 120 => "{$seconds}s ago",
            $seconds < 7200 => intdiv($seconds, 60).'m ago',
            $seconds < 172800 => intdiv($seconds, 3600).'h ago',
            default => intdiv($seconds, 86400).'d ago',
        };
    }

    protected function bytes(int $bytes): string
    {
        $units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
        $i = 0;
        for ($value = $bytes; $value >= 1024 && $i < count($units) - 1; $i++) {
            $value /= 1024;
        }

        return $i === 0 ? "{$bytes} B" : sprintf('%.1f %s', $value, $units[$i]);
    }
}
