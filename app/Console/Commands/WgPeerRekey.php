<?php

namespace App\Console\Commands;

use App\Services\QrCode;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerRekey extends WgCommand
{
    protected $signature = 'wg:peer:rekey
        {link : Interface name}
        {pubkey : Peer public key}
        {--qr : Also print the new client config as a QR code}';

    protected $description = 'Give a peer new keys (its old client config stops working)';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        try {
            $peer = $wg->rekeyPeer($link, $pubkey);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        // Its public key is what it is known by from now on
        $this->info("Rekeyed peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})"));
        $this->line("It was {$pubkey}: the client config with that key no longer works.");

        if ($peer->client_config !== null) {
            $this->line('');
            $this->info('New client configuration:');
            $this->line('');
            $this->line($peer->client_config);
            if ($this->option('qr')) {
                $this->line('');
                try {
                    $this->line(app(QrCode::class)->terminal($peer->client_config));
                } catch (\InvalidArgumentException $e) {
                    $this->warn($e->getMessage());
                }
            }
        }

        return Command::SUCCESS;
    }
}
