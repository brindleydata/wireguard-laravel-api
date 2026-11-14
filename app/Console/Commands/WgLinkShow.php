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
        $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
        $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
        $this->line('');

        foreach ($link->peers as $peer) {
            $this->info("Peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})").($peer->enabled ? '' : ' [disabled]'));
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('PSK: '.($peer->preshared_key ?? '(none)'));
            $this->line('');
        }

        return Command::SUCCESS;
    }
}
