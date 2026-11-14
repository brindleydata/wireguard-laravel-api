<?php

namespace App\Console\Commands;

use App\Services\QrCode;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerCreate extends WgCommand
{
    protected $signature = 'wg:peer:create
        {link : Interface name}
        {--ip= : Peer IP address within the link subnet (auto-assigned if omitted)}
        {--name= : A label for the peer}
        {--networks= : Networks behind the peer, routed to it (site-to-site), e.g. 192.168.1.0/24}
        {--qr : Also print the client config as a QR code}';

    protected $description = 'Create a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $ip = $this->option('ip');

        try {
            $peer = $wg->addPeer($link, $ip, $this->option('name'), $this->option('networks'));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Added peer {$peer->public_key}");
        $this->line("Allowed IPs: {$peer->allowed_ips}");
        $this->line('');

        if ($peer->client_config !== null) {
            $this->info('Peer configuration:');
            $this->line('');
            $this->line($peer->client_config);
            if ($this->option('qr')) {
                $this->line('');
                try {
                    $this->line(app(QrCode::class)->terminal($peer->client_config));
                } catch (\InvalidArgumentException $e) {
                    $this->warn($e->getMessage()); // the peer exists all the same
                }
            }
        }

        return Command::SUCCESS;
    }
}
