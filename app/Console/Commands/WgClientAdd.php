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
        $interface_name = $this->argument('interface');
        $ip = $this->argument('ip');

        try {
            $peer = $wg->addPeer($interface_name, $ip);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Added peer {$peer->public_key}");
        $this->line("Allowed IPs: {$peer->allowed_ips}");
        $this->line('');

        if ($peer->client_config !== null) {
            $this->info('Client configuration:');
            $this->line('');
            $this->line($peer->client_config);
        }

        return Command::SUCCESS;
    }
}
