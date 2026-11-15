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
        {--public-key= : Its own public key (another server, a device that made its own): no private key is kept here}
        {--preshared-key-file= : Its preshared key, from this file (- for stdin) (default: a new one)}
        {--dns= : DNS servers for its client config (default: its link\'s)}
        {--keepalive= : Keepalive interval for its client config (default: its link\'s)}
        {--allowed-ips= : Routes for its client config (AllowedIPs; default: its link\'s)}
        {--enabled= : false adds it disabled: saved, not on the interface (true/false, default: true)}
        {--qr : Also print the client config as a QR code}';

    protected $description = 'Create a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');

        try {
            $peer = $wg->addPeer($link, $this->option('ip'), $this->option('name'), $this->option('networks'), $this->option('remote'),
                $this->option('public-key'), $this->secretFrom('preshared-key-file'), $this->option('dns'), $this->number('keepalive'), $this->option('allowed-ips'),
                $this->flag('enabled') ?? true);
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($peer->toArray(), function () use ($peer) {
            $this->info("Added peer {$peer->public_key}");
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('');

            if ($peer->client_config !== null) {
                // Before the config, not after it: what follows [Interface] is the config
                if ($peer->private_key === null) {
                    $this->warn('Its private key is its own: the device adds it (PrivateKey) to this config.');
                }
                $this->info('Peer configuration:');
                $this->line('');
                $this->line($peer->client_config);
                // A key of its own: no QR code of a config without it
                if ($peer->private_key !== null) {
                    $this->qr($peer->client_config);
                }
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
