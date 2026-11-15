<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\DescribesPeers;
use App\Services\QrCode;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerShow extends WgCommand
{
    use DescribesPeers;

    protected $signature = 'wg:peer {link : Interface name} {pubkey : Peer public key} {--qr : Print it as a QR code, for the WireGuard apps}';

    protected $description = 'Show a WireGuard peer and its client configuration';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        try {
            $peer = $wg->getPeer($link, $pubkey);
            $config = $peer === null ? null : $wg->getPeerConfig($link, $pubkey);
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }
        if ($peer === null) {
            return $this->failed("Peer {$pubkey} not found on {$link}.");
        }

        if ($this->option('qr') && ! $this->json()) {
            if ($config === null) {
                return $this->failed('This peer has no client config: its private key is not stored here.');
            }
            try {
                $this->line(app(QrCode::class)->terminal($config));
            } catch (\InvalidArgumentException $e) {
                return $this->failed($e->getMessage());
            }

            return Command::SUCCESS;
        }

        return $this->respond([...$peer->toArray(), 'client_config' => $config], function () use ($peer, $config) {
            $this->info("Peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})"));
            foreach ($this->details($peer) as $line) {
                $this->line($line);
            }
            $this->line('State: '.$this->state($peer));
            $this->line('');

            if ($config === null) {
                $this->warn('It has no client config: its private key is not stored here.');

                return;
            }
            $this->info('Client configuration:');
            $this->line('');
            $this->line($config);
        });
    }
}
