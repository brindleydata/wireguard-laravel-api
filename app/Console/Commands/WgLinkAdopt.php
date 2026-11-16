<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

class WgLinkAdopt extends WgCommand
{
    protected $signature = 'wg:link:adopt
        {link : Interface name}
        {--dry-run : Only say what would be kept, dropped and applied: nothing is changed}
        {--ifout= : Outbound network interface for NAT (default: the default route\'s)}
        {--forward= : Forward its peers\' traffic (true/false, default: false)}
        {--nat= : NAT masquerading (true/false, default: false)}
        {--inbound= : With forward: let connections that start outside reach peers, not only replies (true/false, default: false)}
        {--destinations= : The only networks traffic out of its tunnel is forwarded and NATed to, comma-separated (default: anywhere)}
        {--allowed-ips= : Allowed IPs for peer configs (default: all traffic)}
        {--dns= : DNS server for peers (default: 8.8.8.8)}
        {--keepalive= : Persistent keepalive interval in seconds (default: 25)}
        {--mtu= : MTU for the interface and its clients (default: the config\'s own, else wg-quick\'s)}
        {--endpoint= : Where its clients connect: a host, or host:port (default: this server\'s name or public IP, detected now and kept)}
        {--allow-default-route= : Let peers route a default route, where the server allows it (true/false, default: false)}
        {--allow-own-networks= : Let peers route networks holding this server\'s own addresses, where the server allows it (true/false, default: false)}';

    protected $description = 'Take a config written by hand or by an older API under management (its key, port, addresses and peers stay)';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');
        $dry_run = (bool) $this->option('dry-run');

        try {
            // An empty option is the default, as with the API's null
            $params = array_filter([
                'ifout' => $this->option('ifout') ?: null,
                'forward' => $this->flag('forward'),
                'nat' => $this->flag('nat'),
                'inbound' => $this->flag('inbound'),
                'destinations' => $this->option('destinations') ?: null,
                'allowed_ips' => $this->option('allowed-ips') ?: null,
                'dns' => $this->option('dns') ?: null,
                'keepalive' => $this->number('keepalive'),
                'mtu' => $this->number('mtu'),
                'endpoint' => $this->option('endpoint') ?: null,
                'allow_default_route' => $this->flag('allow-default-route'),
                'allow_own_networks' => $this->flag('allow-own-networks'),
            ], fn ($value) => $value !== null);

            ['link' => $link, 'adoption' => $adoption] = $wg->adoptLink($name, $params, $dry_run);
        } catch (\Throwable $e) {
            return $this->failed($e);
        }

        // What POST /link/{name}/adopt answers
        return $this->respond([...$link->toArray(), 'adoption' => $adoption], function () use ($link, $adoption, $dry_run) {
            $count = fn (int $n, string $one, string $many) => $n === 1 ? "1 {$one}" : "{$n} {$many}";
            $list = fn (array $items) => $items === [] ? 'nothing' : implode(', ', $items);
            ['kept' => $kept, 'applied' => $applied, 'keys' => $keys] = $adoption;

            $dry_run
                ? $this->info("Adopting link {$link->name} would do this (nothing was changed):")
                : $this->info("Adopted link {$link->name}");
            $this->line('Kept: '.$list(array_filter([
                "public key {$kept['public_key']}",
                "port {$kept['listen_port']}",
                "address {$kept['address']}",
                $kept['address6'] === null ? null : "IPv6 address {$kept['address6']}",
                $count($kept['peers'], 'peer', 'peers').' with their keys and allowed IPs',
            ])));
            // By key only: a line of a config may hold a secret
            $this->line('Dropped: '.$list(array_map(fn (int $lines, string $what) => "{$what} ×{$lines}", $adoption['dropped'], array_keys($adoption['dropped']))));
            $this->line('Applied: '.$list(array_map(
                fn (mixed $value, string $setting) => str_replace('_', ' ', $setting).' '.match (true) {
                    is_bool($value) => $value ? 'on' : 'off',
                    $value === null => $setting === 'destinations' ? 'anywhere' : '(default)',
                    default => $value,
                },
                $applied, array_keys($applied),
            )));

            $this->line('Private keys of its peers: '.$list(array_filter([
                $keys['stored'] === [] ? null : count($keys['stored']).' stored here already',
                $keys['imported'] === [] ? null : count($keys['imported']).' taken over from the client configs an older API kept',
                $keys['own'] === [] ? null : count($keys['own']).' not here (keys of their own: their client configs come without PrivateKey, and without a QR code)',
            ])));
            foreach (['imported' => 'Taken over', 'own' => 'Not here'] as $kind => $label) {
                foreach ($keys[$kind] as $pubkey) {
                    $this->line("  {$label}: {$pubkey}");
                }
            }
            if ($adoption['restarts']) {
                $this->line($dry_run ? 'The link runs: it would restart, and run again as it does now if it did not come up.' : 'The link was restarted with its new config.');
            }
            foreach ($adoption['warnings'] as $warning) {
                $this->warn($warning);
            }
            if ($dry_run && $adoption['dropped'] !== []) {
                $this->line("(What exactly is dropped: sudo grep -nE '^\\s*(#|Pre|Post|SaveConfig)' on its config.)");
            }
        });
    }
}
