<?php

namespace App\Console\Commands;

class WgShow extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:show {link}';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Show Wireguard link information';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $link = $this->argument('link');
        if (!$this->verifyInterface($link)) {
            $this->error("Interface do not exists: {$link}");
            die();
        }

        $link = $this->readLink($link);

        $this->info("Interface {$link->iface}");
        $this->line("Public Key: {$link->public_key}");
        $this->line("Private Key: {$link->private_key}");
        $this->line("Listen Port: {$link->listen_port}");
        $this->line("VPN address: {$link->vpn_address}");
        $this->line("");
        foreach ($link->peers as $id => $peer) {
            $this->info("Peer {$id}");
            $this->line("VPN address: {$peer['ip']}");
            $this->line("PSK: {$peer['psk']}");
            $this->line("");
        }
    }
}
