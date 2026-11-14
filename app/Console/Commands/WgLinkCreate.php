<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkCreate extends WgCommand
{
    protected $signature = 'wg:link:create
        {link : Interface name (max 15 chars)}
        {ip : VPN address in CIDR notation (e.g. 10.0.0.1/24)}
        {--address6= : IPv6 address and prefix too (e.g. fd12:3456:789a::1/64), or "auto" for a random private /64}
        {--port= : Listen port (random if omitted)}
        {--ifout= : Outbound network interface for NAT (auto-detected if omitted)}
        {--dns= : DNS server for peers (default: 8.8.8.8)}
        {--keepalive= : Persistent keepalive interval in seconds (default: 25)}
        {--allowed-ips= : Allowed IPs for peer configs (default: all traffic, 0.0.0.0/0 and ::/0 with IPv6)}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Start the interface after creation (true/false, default: true)}';

    protected $description = 'Create a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');
        $ip = $this->argument('ip');
        $ifout = $this->option('ifout');
        $dns = $this->option('dns');
        $allowed_ips = $this->option('allowed-ips');

        try {
            $port = $this->number('port');
            $keepalive = $this->option('keepalive') === '' ? null : $this->number('keepalive');
            $forward = $this->flag('forward') ?? false;
            $nat = $this->flag('nat') ?? false;
            $up = $this->flag('up') ?? true;

            $link = $wg->createLink($name, $ip, $port, $ifout, $dns, $keepalive, $allowed_ips, $forward, $nat, $up, $this->option('address6'));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Created link {$link->name}");
        $this->line("Public Key: {$link->public_key}");
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("Address: {$link->address}");
        if ($link->address6 !== null) {
            $this->line("IPv6 Address: {$link->address6}");
        }

        return Command::SUCCESS;
    }
}
