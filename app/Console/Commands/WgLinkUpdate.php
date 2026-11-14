<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkUpdate extends WgCommand
{
    protected $signature = 'wg:link:update
        {link : Interface name}
        {--dns= : DNS server for peers ("" goes back to WIREGUARD_DNS)}
        {--keepalive= : Persistent keepalive interval in seconds ("" goes back to WIREGUARD_KEEPALIVE)}
        {--allowed-ips= : Allowed IPs for peer configs ("" goes back to WIREGUARD_ALLOWED_IPS)}
        {--ifout= : Outbound network interface for NAT}
        {--port= : Listen port}
        {--address= : VPN address in CIDR notation}
        {--address6= : IPv6 address and prefix (e.g. fd12:3456:789a::1/64), "auto" for a random private /64, or "none" to remove it}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Bring interface up or down (true/false)}';

    protected $description = 'Update a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        $params = [];

        if ($this->option('dns') !== null) {
            $params['dns'] = $this->option('dns');
        }
        if ($this->option('keepalive') !== null) {
            // "" is not 0 seconds: it takes the link's own value out
            $params['keepalive'] = $this->option('keepalive') === '' ? null : (int) $this->option('keepalive');
        }
        if ($this->option('allowed-ips') !== null) {
            $params['allowed_ips'] = $this->option('allowed-ips');
        }
        if ($this->option('ifout') !== null) {
            $params['ifout'] = $this->option('ifout');
        }
        if ($this->option('port') !== null) {
            $params['port'] = (int) $this->option('port');
        }
        if ($this->option('address') !== null) {
            $params['address'] = $this->option('address');
        }
        if ($this->option('address6') !== null) {
            $params['address6'] = $this->option('address6');
        }
        if ($this->option('forward') !== null) {
            $params['forward'] = filter_var($this->option('forward'), FILTER_VALIDATE_BOOLEAN);
        }
        if ($this->option('nat') !== null) {
            $params['nat'] = filter_var($this->option('nat'), FILTER_VALIDATE_BOOLEAN);
        }
        if ($this->option('up') !== null) {
            $params['up'] = filter_var($this->option('up'), FILTER_VALIDATE_BOOLEAN);
        }

        if (empty($params)) {
            $this->warn('No options provided. Nothing to update.');

            return Command::SUCCESS;
        }

        try {
            $link = $wg->updateLink($name, $params);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Updated link {$link->name}");
        $this->line("Address: {$link->address}");
        $this->line('IPv6 Address: '.($link->address6 ?? '(none)'));
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("Outbound: {$link->ifout}");
        $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
        $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
        $this->line('Up: '.($link->up ? 'yes' : 'no'));

        return Command::SUCCESS;
    }
}
