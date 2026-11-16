<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\DescribesPeers;
use App\DTOs\PeerInfo;
use App\Services\WireGuard;

class WgLinkPeers extends WgCommand
{
    use DescribesPeers;

    protected $signature = 'wg:link:peers {link : Interface name}';

    protected $description = 'List peers for a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $link = $wg->linkOrFail($name);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }

        return $this->respond(array_map(fn (PeerInfo $peer) => $peer->toArray(), $link->peers), function () use ($link) {
            if ($link->peers === []) {
                $this->warn("No peers on {$link->name}.");

                return;
            }

            $this->info("Peers on {$link->name}:");
            $this->line('');

            foreach ($link->peers as $peer) {
                $name = $peer->name === null ? '' : "{$peer->name}  ";
                $this->line("  {$name}{$peer->allowed_ips}  {$peer->public_key}  ".$this->state($peer));
            }
        });
    }
}
