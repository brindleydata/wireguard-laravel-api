<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

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
            return $this->failed($e);
        }

        return $this->respond(['message' => "Removed peer from {$link}"], fn () => $this->info("Removed peer {$pubkey} from {$link}"));
    }
}
