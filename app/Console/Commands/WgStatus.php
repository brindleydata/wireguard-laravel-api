<?php

namespace App\Console\Commands;

use App\Services\Server;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgStatus extends WgCommand
{
    protected $signature = 'wg:status';

    protected $description = 'Show system status';

    public function handle(WireGuard $wg): int
    {
        $server = app(Server::class);

        try {
            $status = $server->status();
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $ip = $server->ip();

        $this->info($status->app['name'].' v'.($status->app['version'] ?? '0.0'));
        $this->line("Hostname: {$status->hostname}");
        $this->line('IPv4: '.($ip['ipv4'] ?? '(none)'));
        $this->line('IPv6: '.($ip['ipv6'] ?? '(none)'));
        $this->line('');
        $this->line("CPU: {$status->cpu['cores']} cores, load {$status->cpu['load']}, {$status->cpu['usage']}%");
        $this->line("RAM: {$status->ram['usage']}% used ({$status->ram['free']} kB free / {$status->ram['total']} kB)");
        $this->line("Disk: {$status->disk['usage']}% used ({$status->disk['free']} free / {$status->disk['size']})");

        return Command::SUCCESS;
    }
}
