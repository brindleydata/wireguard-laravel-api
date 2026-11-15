<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

class WgLinkRekey extends WgCommand
{
    protected $signature = 'wg:link:rekey {link : Interface name}';

    protected $description = 'Give a link new keys (every client then needs its new config)';

    public function handle(WireGuard $wg): int
    {
        try {
            $link = $wg->rekeyLink($this->argument('link'));
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($link->toArray(), function () use ($link) {
            $this->info("Link {$link->name} has new keys. Public Key: {$link->public_key}");
            // The link's public key is in every client config: the ones out there stop working
            $this->warn('Every client needs its new config (wgla peer '.$link->name.' <public key>, or GET /link/'.$link->name.'/peer/{pubkey}/config).');
        });
    }
}
