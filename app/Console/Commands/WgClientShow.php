<?php

namespace App\Console\Commands;

class WgClientShow extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:client:show {link} {ip}';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Create Wireguard VPN Client.';

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
                $found = true;
            }
        }

        if (!$found) {
            $this->warn("Client {$ip} not found in running {$link} configuration!");
        }

        $template = @file_get_contents("/etc/wireguard/clients/{$link}/{$ip}.conf");
        if (empty($template)) {
            $this->error("Could not find configuration for client {$ip} on {$link}.");
            die(1);
        }

        $this->info("Client {$ip} template:");
        $this->line("");
        echo $template;
    }
}
