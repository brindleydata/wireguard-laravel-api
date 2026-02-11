<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerUpdate extends WgCommand
{
    protected $signature = 'wg:peer:update
        {link : Interface name}
        {pubkey : Peer public key}
        {--dns= : DNS server override for client config}
        {--allowed-ips= : Allowed IPs override}';

    protected $description = 'Update a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        $params = [];

        if ($this->option('dns') !== null) {
            $params['dns'] = $this->option('dns');
        }
        if ($this->option('allowed-ips') !== null) {
            $params['allowed_ips'] = $this->option('allowed-ips');
        }

        if (empty($params)) {
            $this->warn('No options provided. Nothing to update.');

            return Command::SUCCESS;
        }

        try {
            $peer = $wg->updatePeer($link, $pubkey, $params);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Updated peer {$peer->public_key}");
        $this->line("Allowed IPs: {$peer->allowed_ips}");

        if ($peer->client_config !== null) {
            $this->line('');
            $this->info('Updated client configuration:');
            $this->line('');
            $this->line($peer->client_config);
        }

        return Command::SUCCESS;
    }
}
