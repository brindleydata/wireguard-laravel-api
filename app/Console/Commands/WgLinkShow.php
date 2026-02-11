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
        $this->line("Public Key: {$link->public_key}");
        $this->line("Private Key: {$link->private_key}");
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("VPN Address: {$link->address}");
        $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
        $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
        $this->line('');

        foreach ($link->peers as $peer) {
            $this->info("Peer {$peer->public_key}");
            $this->line("Allowed IPs: {$peer->allowed_ips}");
            $this->line('PSK: '.($peer->preshared_key ?? '(none)'));
            $this->line('');
        }

        return Command::SUCCESS;
    }
}
