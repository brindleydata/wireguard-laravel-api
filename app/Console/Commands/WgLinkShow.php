<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkShow extends WgCommand
{
    protected $signature = 'wg:link {link : Interface name}';

    protected $description = 'Show WireGuard link details';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        $link = $wg->getLink($name);
        if ($link === null) {
            $this->error("Link does not exist: {$name}");

            return Command::FAILURE;
        }

        $this->info("Link {$link->name}");
        $this->line('Interface: '.($link->interface ?? '(down)'));
        $this->line("Public Key: {$link->public_key}");
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("VPN Address: {$link->address}");
        if ($link->address6 !== null) {
            $this->line("VPN Address (IPv6): {$link->address6}");
        }
        $this->line('MTU: '.($link->mtu ?? '(default)'));
        $this->line("Outbound: {$link->ifout}");
        $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
        $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
        if ($link->firewall === 'missing') {
            $this->error("Its firewall rules are missing. Put them back with: wgla link:repair {$link->name}");
        }
        // What its clients get, unless a peer has its own
        $client = $link->clientSettings();
        $this->line('Client DNS: '.($client['dns'] ?? '(default)'));
        $this->line('Client keepalive: '.($client['keepalive'] ?? '(default)'));
        $this->line('Client allowed IPs: '.($client['allowed_ips'] ?? '(default)'));
        $this->line('');

        foreach ($link->peers as $peer) {
            $this->info("Peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})").($peer->enabled ? '' : ' [disabled]'));
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('PSK: '.($peer->preshared_key ?? '(none)'));
            if ($peer->remote !== null) {
                $this->line("Remote: {$peer->remote}");
            }
            if (($own = array_filter($peer->clientSettings(), fn ($value) => $value !== null)) !== []) {
                $this->line('Own client settings: '.implode(', ', array_map(fn ($value, string $key) => "{$key} {$value}", $own, array_keys($own))));
            }
            $this->line('');
        }

        return Command::SUCCESS;
    }
}
