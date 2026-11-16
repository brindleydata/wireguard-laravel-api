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
            // Says which isn't there, the link or the peer
            $peer = $wg->peerOrFail($link, $pubkey);
            $config = $wg->getPeerConfig($link, $pubkey);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }

        if ($this->option('qr') && ! $this->json()) {
            try {
                // The whole config, its private key included: a peer with a key of its own has none
                $config = $wg->getPeerConfig($link, $pubkey, with_key: true)
                    ?? throw new \InvalidArgumentException("There is no client config of a peer of {$link}: it runs without a config here.");
                $this->line(app(QrCode::class)->terminal($config));
            } catch (\InvalidArgumentException $e) {
                return $this->failed($e);
            }

            return Command::SUCCESS;
        }

        return $this->respond([...$peer->toArray(), 'client_config' => $config], function () use ($peer, $config, $link) {
            $this->info("Peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})"));
            foreach ($this->details($peer) as $line) {
                $this->line($line);
            }
            $this->line('State: '.$this->state($peer));
            $this->line('');

            if ($config === null) {
                $this->warn("There is no client config of it: {$link} runs without a config here.");

                return;
            }
            // Before the config, which ends the output: `wgla peer … | sed -n '/^\[Interface\]/,$p'`
            // is a config wg can read
            if (! preg_match('/^PrivateKey = /m', $config)) {
                $this->warn('Its private key is its own, not stored here: the device adds it (PrivateKey).');
            }
            $this->info('Client configuration:');
            $this->line('');
            $this->line($config);
        });
    }
}
