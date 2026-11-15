<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

class WgPeerUpdate extends WgCommand
{
    protected $signature = 'wg:peer:update
        {link : Interface name}
        {pubkey : Peer public key}
        {--ip= : New tunnel address within the link subnet}
        {--dns= : DNS servers for this peer\'s client config ("" goes back to the link\'s)}
        {--allowed-ips= : Routes for this peer\'s client config (AllowedIPs; "" goes back to the link\'s)}
        {--keepalive= : Keepalive interval for this peer\'s client config ("" goes back to the link\'s)}
        {--name= : A label for the peer ("" removes it)}
        {--enabled= : false takes the peer off the interface, true puts it back}
        {--networks= : Networks behind the peer, routed to it ("" removes them)}
        {--remote= : host:port the server connects to ("" removes it: the peer connects)}';

    protected $description = 'Update a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $pubkey = $this->argument('pubkey');

        try {
            $params = array_filter([
                'ip' => $this->option('ip'),
                'dns' => $this->option('dns'),
                'allowed_ips' => $this->option('allowed-ips'),
                'name' => $this->option('name'),
                'enabled' => $this->flag('enabled'),
                'networks' => $this->option('networks'),
                'remote' => $this->option('remote'),
            ], fn ($value) => $value !== null);
            if ($this->option('keepalive') !== null) {
                // "" is not 0 seconds: it takes the peer's own value out
                $params['keepalive'] = $this->option('keepalive') === '' ? null : $this->number('keepalive');
            }

            if ($params === []) {
                return $this->respond(['message' => 'No options given: nothing to update.'], fn () => $this->warn('No options provided. Nothing to update.'));
            }

            $peer = $wg->updatePeer($link, $pubkey, $params);
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($peer->toArray(), function () use ($peer) {
            $this->info("Updated peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})"));
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('Enabled: '.($peer->enabled ? 'yes' : 'no'));

            if ($peer->client_config !== null) {
                $this->line('');
                $this->info('Updated client configuration:');
                $this->line('');
                $this->line($peer->client_config);
            }
        });
    }
}
