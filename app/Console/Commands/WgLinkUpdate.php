<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

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
        {--address6= : IPv6 address and prefix (e.g. fd12:3456:789a::1/64), "auto" for a random private /64 (a link with one keeps it), or "none" to remove it}
        {--mtu= : MTU for the interface and its clients ("" goes back to wg-quick\'s)}
        {--forward= : Enable or disable IP forwarding (true/false)}
        {--nat= : Enable or disable NAT masquerading (true/false)}
        {--up= : Bring interface up or down (true/false)}
        {--inbound= : With forward: let connections that start outside reach peers, not only replies (true/false)}
        {--allow-default-route= : Let peers route a default route, where the server allows it (true/false)}
        {--allow-own-networks= : Let peers route networks holding this server\'s own addresses, where the server allows it (true/false)}
        {--endpoint= : Where its clients connect: a host, or host:port ("" detects it anew); every client needs its new config}
        {--destinations= : The only networks traffic out of its tunnel is forwarded and NATed to, comma-separated ("": anywhere again)}';

    protected $description = 'Update a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $params = array_filter([
                'dns' => $this->option('dns'),
                'allowed_ips' => $this->option('allowed-ips'),
                'destinations' => $this->option('destinations'),
                'ifout' => $this->option('ifout'),
                'port' => $this->number('port'),
                'address' => $this->option('address'),
                'address6' => $this->option('address6'),
                'forward' => $this->flag('forward'),
                'nat' => $this->flag('nat'),
                'up' => $this->flag('up'),
                'inbound' => $this->flag('inbound'),
                'allow_default_route' => $this->flag('allow-default-route'),
                'allow_own_networks' => $this->flag('allow-own-networks'),
                'move_peers' => $this->option('move-peers') ?: null,
            ], fn ($value) => $value !== null);
            if ($this->option('endpoint') !== null) {
                $params['endpoint'] = $this->option('endpoint') ?: null; // "": detected anew
            }
            foreach (['keepalive', 'mtu'] as $option) {
                if ($this->option($option) !== null) {
                    // "" is not 0: it takes the link's own value out
                    $params[$option] = $this->option($option) === '' ? null : $this->number($option);
                }
            }

            // None: the link as it is, as PATCH {} answers
            $link = $wg->updateLink($name, $params);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }
        if ($params === []) {
            return $this->respond($link->toArray(), fn () => $this->warn('No options given: nothing to update.'));
        }

        return $this->respond($link->toArray(), function () use ($link) {
            $this->info("Updated link {$link->name}");
            $this->line("Address: {$link->address}");
            $this->line('IPv6 Address: '.($link->address6 ?? '(none)'));
            $this->line("Listen Port: {$link->listen_port}");
            $this->line('Endpoint: '.($link->endpoint ?? '(detected)'));
            $this->line('MTU: '.($link->mtu ?? '(default)'));
            $this->line("Outbound: {$link->ifout}");
            $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
            $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
            $this->line('Inbound: '.($link->inbound ? 'connections from outside reach peers' : 'replies only'));
            $this->line('Destinations: '.($link->destinations ?? 'anywhere'));
            $this->line('Peers may route: '.$this->routesAllowed($link));
            $this->line('Up: '.($link->up ? 'yes' : 'no'));
        });
    }
}
