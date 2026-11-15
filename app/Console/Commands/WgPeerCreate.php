<?php

namespace App\Console\Commands;

use App\Services\QrCode;
use App\Services\WireGuard;

class WgPeerCreate extends WgCommand
{
    protected $signature = 'wg:peer:create
        {link : Interface name}
        {--ip= : Peer IP address within the link subnet (auto-assigned if omitted)}
        {--name= : A label for the peer}
        {--networks= : Networks behind the peer, routed to it (site-to-site), e.g. 192.168.1.0/24}
        {--remote= : host:port the server connects to, when the peer can\'t be the one to connect}
        {--qr : Also print the client config as a QR code}';

    protected $description = 'Create a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');

        try {
            $peer = $wg->addPeer($link, $this->option('ip'), $this->option('name'), $this->option('networks'), $this->option('remote'));
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($peer->toArray(), function () use ($peer) {
            $this->info("Added peer {$peer->public_key}");
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('');

            if ($peer->client_config !== null) {
                $this->info('Peer configuration:');
                $this->line('');
                $this->line($peer->client_config);
                $this->qr($peer->client_config);
            }
        });
    }

    /** With --qr: the client config once more, to scan. */
    protected function qr(string $config): void
    {
        if (! $this->option('qr')) {
            return;
        }

        $this->line('');
        try {
            $this->line(app(QrCode::class)->terminal($config));
        } catch (\InvalidArgumentException $e) {
            $this->warn($e->getMessage()); // the peer exists all the same
        }
    }
}
