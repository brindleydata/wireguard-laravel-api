<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgShow extends WgCommand
{
    protected $signature = 'wg:show {interface}';

    protected $description = 'Show WireGuard interface information';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('interface');

        $interface = $wg->getInterface($name);
        if ($interface === null) {
            $this->error("Interface does not exist: {$name}");

            return Command::FAILURE;
        }

        $this->info("Interface {$interface->name}");
        $this->line("Public Key: {$interface->publicKey}");
        $this->line("Private Key: {$interface->privateKey}");
        $this->line("Listen Port: {$interface->listenPort}");
        $this->line("VPN Address: {$interface->address}");
        $this->line('');

        foreach ($interface->peers as $peer) {
            $this->info("Peer {$peer->publicKey}");
            $this->line("VPN Address: {$peer->allowedIps}");
            $this->line('PSK: '.($peer->presharedKey ?? '(none)'));
            $this->line('');
        }

        return Command::SUCCESS;
    }
}
