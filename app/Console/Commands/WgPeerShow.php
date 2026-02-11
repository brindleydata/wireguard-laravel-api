<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerShow extends WgCommand
{
    protected $signature = 'wg:peer {link : Interface name} {pubkey : Peer public key}';

    protected $description = 'Show WireGuard peer configuration';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        $config = $wg->getPeerConfig($link, $pubkey);
        if ($config === null) {
            $this->error("Could not find configuration for peer {$pubkey} on {$link}.");

            return Command::FAILURE;
        }

        $this->info("Peer {$pubkey} configuration:");
        $this->line('');
        $this->line($config);

        return Command::SUCCESS;
    }
}
