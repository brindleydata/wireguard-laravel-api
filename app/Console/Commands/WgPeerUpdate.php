<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerUpdate extends WgCommand
{
    protected $signature = 'wg:peer:update
        {link : Interface name}
        {pubkey : Peer public key}
        {--ip= : New tunnel address within the link subnet}
        {--dns= : DNS servers for this peer\'s client config}
        {--allowed-ips= : Routes for this peer\'s client config (AllowedIPs)}
        {--name= : A label for the peer ("" removes it)}
        {--enabled= : false takes the peer off the interface, true puts it back}
        {--networks= : Networks behind the peer, routed to it ("" removes them)}';

    protected $description = 'Update a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        $params = [];

        if ($this->option('ip') !== null) {
            $params['ip'] = $this->option('ip');
        }
        if ($this->option('dns') !== null) {
            $params['dns'] = $this->option('dns');
        }
        if ($this->option('allowed-ips') !== null) {
            $params['allowed_ips'] = $this->option('allowed-ips');
        }
        if ($this->option('name') !== null) {
            $params['name'] = $this->option('name');
        }
        if ($this->option('enabled') !== null) {
            $params['enabled'] = filter_var($this->option('enabled'), FILTER_VALIDATE_BOOLEAN);
        }
        if ($this->option('networks') !== null) {
            $params['networks'] = $this->option('networks');
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

        $this->info("Updated peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})"));
        $this->line("Allowed IPs: {$peer->allowed_ips}");
        $this->line('Enabled: '.($peer->enabled ? 'yes' : 'no'));

        if ($peer->client_config !== null) {
            $this->line('');
            $this->info('Updated client configuration:');
            $this->line('');
            $this->line($peer->client_config);
        }

        return Command::SUCCESS;
    }
}
