<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgCreate extends WgCommand
{
    protected $signature = 'wg:create {interface} {ip} {port?} {ifout?}';

    protected $description = 'Create a WireGuard interface';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('interface');
        $ip = $this->argument('ip');
        $port = $this->argument('port') ? (int) $this->argument('port') : null;
        $ifout = $this->argument('ifout');

        try {
            $interface = $wg->createInterface($name, $ip, $port, $ifout);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Created interface {$interface->name}");
        $this->line("Public Key: {$interface->publicKey}");
        $this->line("Listen Port: {$interface->listenPort}");
        $this->line("Address: {$interface->address}");

        return Command::SUCCESS;
    }
}
