<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerShow extends WgCommand
{
    protected $signature = 'wg:peer:show {link} {ip}';

    protected $description = 'Show WireGuard peer configuration';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $ip = $this->argument('ip');

        if (! filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->error('Invalid IP address.');

            return Command::FAILURE;
        }

        $config = $wg->getPeerConfig($link, $ip);
        if ($config === null) {
            $this->error("Could not find configuration for peer {$ip} on {$link}.");

            return Command::FAILURE;
        }

        $this->info("Peer {$ip} configuration:");
        $this->line('');
        $this->line($config);

        return Command::SUCCESS;
    }
}
