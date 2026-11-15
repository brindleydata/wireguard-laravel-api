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
        {--up= : Start the interface after creation (true/false, default: true)}
        {--inbound= : With forward: let connections that start outside reach peers, not only replies (true/false, default: false)}
        {--allow-default-route= : Let peers route a default route, where the server allows it (true/false, default: false)}
        {--allow-own-networks= : Let peers route networks holding this server\'s own addresses, where the server allows it (true/false, default: false)}
        {--endpoint= : Where its clients connect: a host, or host:port (default: this server\'s name or public IP, detected now and kept)}
        {--private-key-file= : Its own private key, from this file (- for stdin), to move a link here (default: a new one)}';

    protected $description = 'Create a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        try {
            // An empty option is the default, as with the API's null: `--mtu=` as no --mtu
            $link = $wg->createLink(
                $this->argument('link'),
                $this->argument('ip'),
                $this->number('port'),
                $this->option('ifout') ?: null,
                $this->option('dns'),
                $this->number('keepalive'),
                $this->option('allowed-ips'),
                $this->flag('forward') ?? false,
                $this->flag('nat') ?? false,
                $this->flag('up') ?? true,
                $this->option('address6'),
                $this->number('mtu'),
                $this->flag('inbound') ?? false,
                $this->flag('allow-default-route') ?? false,
                $this->flag('allow-own-networks') ?? false,
                $this->option('endpoint') ?: null,
                $this->secretFrom('private-key-file'),
            );
        } catch (\Throwable $e) {
            return $this->failed($e->getMessage());
        }

        return $this->respond($link->toArray(), function () use ($link) {
            $this->info("Created link {$link->name}");
            $this->line("Public Key: {$link->public_key}");
            $this->line("Listen Port: {$link->listen_port}");
            $this->line("Endpoint: {$link->endpoint}");
            $this->line("Address: {$link->address}");
            if ($link->address6 !== null) {
                $this->line("IPv6 Address: {$link->address6}");
            }
        });
    }
}
