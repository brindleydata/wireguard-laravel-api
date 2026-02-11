<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgPeerCreate extends WgCommand
{
    protected $signature = 'wg:peer:create {link : Interface name} {--ip= : Peer IP address within the link subnet (auto-assigned if omitted)}';

    protected $description = 'Create a WireGuard peer';

    public function handle(WireGuard $wg): int
    {
        $link = $this->argument('link');
        $ip = $this->option('ip');

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
