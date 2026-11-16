<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\DescribesPeers;
use App\Services\WireGuard;

class WgLinkShow extends WgCommand
{
    use DescribesPeers;

    protected $signature = 'wg:link {link : Interface name}';

    protected $description = 'Show WireGuard link details';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $link = $wg->linkOrFail($name);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }

        return $this->respond($link->toArray(), function () use ($link) {
            $this->info("Link {$link->name}");
            $this->line('Interface: '.($link->interface ?? '(down)'));
            $this->line("Public Key: {$link->public_key}");
            $this->line("Listen Port: {$link->listen_port}");
            $this->line('Endpoint: '.($link->endpoint ?? '(detected)'));
            $this->line("VPN Address: {$link->address}");
            if ($link->address6 !== null) {
                $this->line("VPN Address (IPv6): {$link->address6}");
            }
            $this->line('MTU: '.($link->mtu ?? '(default)'));
            $this->line("Outbound: {$link->ifout}");
            $this->line('Forward: '.($link->forward ? 'enabled' : 'disabled'));
            $this->line('NAT: '.($link->nat ? 'enabled' : 'disabled'));
            $this->line('Inbound: '.($link->inbound ? 'connections from outside reach peers' : 'replies only'));
            $this->line('Destinations: '.($link->destinations ?? 'anywhere'));
            $this->line('Peers may route: '.$this->routesAllowed($link));
            if (! $link->managed) {
                $this->warn("Not managed here: its config has what this app doesn't write, or it runs without a config here. A config can be taken under management: wgla link:adopt {$link->name} --dry-run");
            }
            if ($link->firewall === 'missing') {
                $this->error("Its firewall rules are missing. Put them back with: wgla link:repair {$link->name}");
            }
            // What its clients get, unless a peer has its own
            $client = $link->clientSettings();
            $this->line('Client DNS: '.($client['dns'] ?? '(default)'));
            $this->line('Client keepalive: '.($client['keepalive'] ?? '(default)'));
            $this->line('Client allowed IPs: '.($client['allowed_ips'] ?? '(default)'));
            $this->line('');

            foreach ($link->peers as $peer) {
                $this->info("Peer {$peer->public_key}".($peer->name === null ? '' : " ({$peer->name})").($peer->enabled ? '' : ' [disabled]'));
                foreach ($this->details($peer) as $line) {
                    $this->line($line);
                }
                $this->line('');
            }
        });
    }
}
