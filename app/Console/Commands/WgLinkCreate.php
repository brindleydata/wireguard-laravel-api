<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkCreate extends WgCommand
{
    protected $signature = 'wg:link:create
        {link : Interface name (max 15 chars)}
        {ip : VPN address in CIDR notation (e.g. 10.0.0.1/24)}
        {--port= : Listen port (random if omitted)}
        {--ifout= : Outbound network interface for NAT (auto-detected if omitted)}
        {--dns= : DNS server for peers (default: WIREGUARD_DNS)}
        {--keepalive= : Persistent keepalive interval in seconds (default: WIREGUARD_KEEPALIVE)}
        {--allowed-ips= : Allowed IPs for peer configs (default: WIREGUARD_ALLOWED_IPS)}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Start the interface after creation (true/false, default: true)}';

    protected $description = 'Create a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');
        $ip = $this->argument('ip');
        $port = $this->option('port') !== null ? (int) $this->option('port') : null;
        $ifout = $this->option('ifout');
        $dns = $this->option('dns');
        $keepalive = $this->option('keepalive') !== null ? (int) $this->option('keepalive') : null;
        $allowed_ips = $this->option('allowed-ips');
        $forward = $this->option('forward') !== null && filter_var($this->option('forward'), FILTER_VALIDATE_BOOLEAN);
        $nat = $this->option('nat') !== null && filter_var($this->option('nat'), FILTER_VALIDATE_BOOLEAN);
        $up = $this->option('up') === null || filter_var($this->option('up'), FILTER_VALIDATE_BOOLEAN);

        try {
            $link = $wg->createLink($name, $ip, $port, $ifout, $dns, $keepalive, $allowed_ips, $forward, $nat, $up);
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
