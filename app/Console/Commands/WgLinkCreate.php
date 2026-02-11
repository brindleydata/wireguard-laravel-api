<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkCreate extends WgCommand
{
    protected $signature = 'wg:link:create {link} {ip} {port?} {ifout?} {--dns=} {--keepalive=} {--allowed-ips=}';

    protected $description = 'Create a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');
        $ip = $this->argument('ip');
        $port = $this->argument('port') ? (int) $this->argument('port') : null;
        $ifout = $this->argument('ifout');
        $dns = $this->option('dns');
        $keepalive = $this->option('keepalive') !== null ? (int) $this->option('keepalive') : null;
        $allowed_ips = $this->option('allowed-ips');

        try {
            $link = $wg->createLink($name, $ip, $port, $ifout, $dns, $keepalive, $allowed_ips);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Created link {$link->name}");
        $this->line("Public Key: {$link->public_key}");
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("Address: {$link->address}");

        return Command::SUCCESS;
    }
}
