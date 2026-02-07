<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgClientShow extends WgCommand
{
    protected $signature = 'wg:client:show {interface} {ip}';

    protected $description = 'Show WireGuard VPN client configuration';

    public function handle(WireGuard $wg): int
    {
        $interface_name = $this->argument('interface');
        $ip = $this->argument('ip');

        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->error('Invalid IP address.');

            return Command::FAILURE;
        }

        $config = $wg->getPeerConfig($interface_name, $ip);
        if ($config === null) {
            $this->error("Could not find configuration for client {$ip} on {$interface_name}.");

            return Command::FAILURE;
        }

        $this->info("Client {$ip} configuration:");
        $this->line('');
        $this->line($config);

        return Command::SUCCESS;
    }
}
