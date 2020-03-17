<?php

namespace App\Console\Commands;

class WgClientDelete extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:client:delete {link} {ip}';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Delete Wireguard VPN Client.';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $link = $this->argument('link');
        $iface = $this->readLink($link);

        $ip = $this->argument('ip');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->error("Invalid IP address.");
            die(1);
        }

        $found = false;
        foreach ($iface->peers as $id => $peer) {
            if ("{$ip}/32" == $peer['ip']) {
                $this->system("wg set {$link} peer {$id} remove", "Could not delete Client.", true);
                $found = true;
            }
        }

        if (!$found) {
            $this->warn("Client {$ip} not found in {$link}");
        }
    }
}
