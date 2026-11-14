<?php

namespace App\Console\Commands;

use App\DTOs\PeerInfo;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkPeers extends WgCommand
{
    protected $signature = 'wg:link:peers {link : Interface name}';

    protected $description = 'List peers for a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        $link = $wg->getLink($name);
        if ($link === null) {
            $this->error("Link does not exist: {$name}");

            return Command::FAILURE;
        }

        if (empty($link->peers)) {
            $this->warn("No peers on {$name}.");

            return Command::SUCCESS;
        }

        $this->info("Peers on {$name}:");
        $this->line('');

        foreach ($link->peers as $peer) {
            $this->line("  {$peer->allowed_ips}  {$peer->public_key}  ".$this->state($peer));
        }

        return Command::SUCCESS;
    }

    protected function state(PeerInfo $peer): string
    {
        return match ($peer->connected()) {
            null => '(link down)',
            false => $peer->latest_handshake === null ? 'never connected' : 'last seen '.$this->ago($peer->latest_handshake),
            true => sprintf('connected from %s, %s; ↓%s ↑%s', $peer->endpoint, $this->ago($peer->latest_handshake),
                $this->bytes($peer->transfer_rx), $this->bytes($peer->transfer_tx)),
        };
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
