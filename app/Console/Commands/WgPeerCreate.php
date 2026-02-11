<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerCreate extends WgCommand
{
    protected $signature = 'wg:peer:create {link} {ip}';

    protected $description = 'Create a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $ip = $this->argument('ip');

        try {
            $peer = $wg->addPeer($link, $ip);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Added peer {$peer->public_key}");
        $this->line("Allowed IPs: {$peer->allowed_ips}");
        $this->line('');

        if ($peer->client_config !== null) {
            $this->info('Peer configuration:');
            $this->line('');
            $this->line($peer->client_config);
        }

        return Command::SUCCESS;
    }
}
