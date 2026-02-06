<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgCommand extends Command
{
    protected $signature = 'wg:help';

    protected $description = 'Show prerequisites';

    public function handle(WireGuard $wg): int
    {
        $this->info('Prerequisites before running:');
        $this->line('');
        $this->line('sudo sysctl -w net.ipv4.ip_forward=1');
        $this->line('sudo sed -i "s:#${NET_FORWARD}:${NET_FORWARD}:" /etc/sysctl.conf');
        $this->line('');
        $this->line('sudo mkdir -p /etc/wireguard/clients');
        $this->line('sudo chmod -R 770 /etc/wireguard && sudo chown -R root:www-data /etc/wireguard');
        $this->line('sudo chmod u+s `which wg` `which wg-quick` `which ip` `which systemctl`');
        $this->line('');
        $this->warn('Ensure your security twice!');
        $this->warn('Do not allow other users on this VPN host and do not allow other significant daemons on it.');
        $this->line('');

        return Command::SUCCESS;
    }
}
