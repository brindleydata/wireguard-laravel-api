<?php

namespace App\Console\Commands;

class WgClientAdd extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:client:add {link} {ip}';

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

        foreach ($iface->peers as $id => $peer) {
            if ("{$ip}/32" == $peer['ip']) {
                $this->error("IP address {$ip} had been registered already.");
                die(1);
            }
        }

        $privkey = $this->genPrivKey();
        $pubkey = $this->genPubKey($privkey);
        $psk = $this->genPsk();

        $this->system("bash -c 'wg set {$link} peer {$pubkey} preshared-key <(echo {$psk}) allowed-ips {$ip}/32'", "Could not add Client.", true);

        $endpoint = env('WIREGUARD_ENDPOINT_IP');
        $allowed_ips = env('WIREGUARD_ALLOWED_IPS');
        $template = <<<EOF
        [Interface]
        PrivateKey = {$privkey}
        Address    = {$ip}/32
        DNS        = 8.8.8.8

        [Peer]
        PublicKey    = {$iface->public_key}
        PresharedKey = {$psk}
        AllowedIPs   = {$allowed_ips}
        Endpoint     = {$endpoint}:{$iface->listen_port}
        PersistentKeepalive = 25
        EOF;

        @mkdir("/etc/wireguard/clients/{$link}", 0770);
        $ret = $this->system("echo '{$template}\n\n' > '/etc/wireguard/clients/{$link}/{$ip}.conf'", "Could not write '/etc/wireguard/clients/{$link}/{$ip}.conf'");
        if ($ret === false) {
            $this->error("Manual client configuration:");
            $this->line("");
            $this->info($template);
            $this->line("");
        }

        return $template;
    }
}
