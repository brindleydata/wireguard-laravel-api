<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgClientDelete extends WgCommand
{
    protected $signature = 'wg:client:delete {interface} {ip}';

    protected $description = 'Delete a WireGuard VPN client';

    public function handle(WireGuard $wg): int
    {
        $interface_name = $this->argument('interface');
        $ip = $this->argument('ip');

        try {
            $wg->removePeer($interface_name, $ip);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Removed peer {$ip} from {$interface_name}");

        return Command::SUCCESS;
    }
}
