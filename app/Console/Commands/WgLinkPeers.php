<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkPeers extends WgCommand
{
    protected $signature = 'wg:link:peers {link}';

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
            $this->line("  {$peer->allowed_ips}  {$peer->public_key}");
        }

        return Command::SUCCESS;
    }
}
