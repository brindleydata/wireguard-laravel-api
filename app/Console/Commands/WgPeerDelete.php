<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerDelete extends WgCommand
{
    protected $signature = 'wg:peer:delete {link} {ip}';

    protected $description = 'Delete a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $ip = $this->argument('ip');

        try {
            $wg->removePeer($link, $ip);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Removed peer {$ip} from {$link}");

        return Command::SUCCESS;
    }
}
