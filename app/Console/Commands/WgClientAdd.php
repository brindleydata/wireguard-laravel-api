<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgClientAdd extends WgCommand
{
    protected $signature = 'wg:client:add {interface} {ip}';

    protected $description = 'Create a WireGuard VPN client';

    public function handle(WireGuard $wg): int
    {
        $interfaceName = $this->argument('interface');
        $ip = $this->argument('ip');

        try {
            $peer = $wg->addPeer($interfaceName, $ip);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Added peer {$peer->publicKey}");
        $this->line("Allowed IPs: {$peer->allowedIps}");
        $this->line('');

        if ($peer->clientConfig !== null) {
            $this->info('Client configuration:');
            $this->line('');
            $this->line($peer->clientConfig);
        }

        return Command::SUCCESS;
    }
}
