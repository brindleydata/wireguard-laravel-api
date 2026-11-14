<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

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
        {--mtu= : MTU for the interface and its clients (default: wg-quick\'s, usually 1420)}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Start the interface after creation (true/false, default: true)}';

    protected $description = 'Create a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        try {
            $link = $wg->createLink(
                $this->argument('link'),
                $this->argument('ip'),
                $this->number('port'),
                $this->option('ifout'),
                $this->option('dns'),
                $this->option('keepalive') === '' ? null : $this->number('keepalive'),
                $this->option('allowed-ips'),
                $this->flag('forward') ?? false,
                $this->flag('nat') ?? false,
                $this->flag('up') ?? true,
                $this->option('address6'),
                $this->number('mtu'),
            );
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($link->toArray(), function () use ($link) {
            $this->info("Created link {$link->name}");
            $this->line("Public Key: {$link->public_key}");
            $this->line("Listen Port: {$link->listen_port}");
            $this->line("Address: {$link->address}");
            if ($link->address6 !== null) {
                $this->line("IPv6 Address: {$link->address6}");
            }
        });
    }
}
