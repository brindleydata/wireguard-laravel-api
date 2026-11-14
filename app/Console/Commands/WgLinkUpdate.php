<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkUpdate extends WgCommand
{
    protected $signature = 'wg:link:update
        {link : Interface name}
        {--dns= : DNS server for peers ("" goes back to the default, 8.8.8.8)}
        {--keepalive= : Persistent keepalive interval in seconds ("" goes back to the default, 25)}
        {--allowed-ips= : Allowed IPs for peer configs ("" goes back to the default, all traffic)}
        {--ifout= : Outbound network interface for NAT}
        {--port= : Listen port}
        {--address= : VPN address in CIDR notation (without a mask: the current one)}
        {--move-peers : With --address in another subnet: peers keep their host number there (clients need their new config)}
        {--address6= : IPv6 address and prefix (e.g. fd12:3456:789a::1/64), "auto" for a random private /64, or "none" to remove it}
        {--mtu= : MTU for the interface and its clients ("" goes back to wg-quick\'s)}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Bring interface up or down (true/false)}';

    protected $description = 'Update a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $params = array_filter([
                'dns' => $this->option('dns'),
                'allowed_ips' => $this->option('allowed-ips'),
                'ifout' => $this->option('ifout'),
                'port' => $this->number('port'),
                'address' => $this->option('address'),
                'address6' => $this->option('address6'),
                'forward' => $this->flag('forward'),
                'nat' => $this->flag('nat'),
                'up' => $this->flag('up'),
                'move_peers' => $this->option('move-peers') ?: null,
            ], fn ($value) => $value !== null);
            foreach (['keepalive', 'mtu'] as $option) {
                if ($this->option($option) !== null) {
                    // "" is not 0: it takes the link's own value out
                    $params[$option] = $this->option($option) === '' ? null : $this->number($option);
                }
            }

            if ($params === []) {
                $this->warn('No options provided. Nothing to update.');

                return Command::SUCCESS;
            }

            $link = $wg->updateLink($name, $params);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Updated link {$link->name}");
        $this->line("Address: {$link->address}");
        $this->line('IPv6 Address: '.($link->address6 ?? '(none)'));
        $this->line("Listen Port: {$link->listen_port}");
        $this->line('MTU: '.($link->mtu ?? '(default)'));
        $this->line("Outbound: {$link->ifout}");
        $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
        $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
        $this->line('Up: '.($link->up ? 'yes' : 'no'));

        return Command::SUCCESS;
    }
}
