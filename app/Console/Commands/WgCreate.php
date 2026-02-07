<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgCreate extends WgCommand
{
    protected $signature = 'wg:create {interface} {ip} {port?} {ifout?} {--dns=} {--keepalive=} {--allowed-ips=}';

    protected $description = 'Create a WireGuard interface';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('interface');
        $ip = $this->argument('ip');
        $port = $this->argument('port') ? (int) $this->argument('port') : null;
        $ifout = $this->argument('ifout');
        $dns = $this->option('dns');
        $keepalive = $this->option('keepalive') !== null ? (int) $this->option('keepalive') : null;
        $allowedIps = $this->option('allowed-ips');

        try {
            $interface = $wg->createInterface($name, $ip, $port, $ifout, $dns, $keepalive, $allowedIps);
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
