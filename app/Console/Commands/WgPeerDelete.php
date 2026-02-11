<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerDelete extends WgCommand
{
    protected $signature = 'wg:peer:delete {link : Interface name} {pubkey : Peer public key}';

    protected $description = 'Delete a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        try {
            $wg->removePeer($link, $pubkey);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Removed peer {$pubkey} from {$link}");

        return Command::SUCCESS;
    }
}
