<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;

class WgCommand extends Command
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:help';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Show prerequisities';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $this->info('Prerequisities before running:');
        $this->line('');
        $this->line('sudo sysctl -w net.ipv4.ip_forward=1');
        $this->line('sudo sed -i "s:#${NET_FORWARD}:${NET_FORWARD}:" /etc/sysctl.conf');
        $this->line('');
        $this->line('sudo mkdir -p /etc/wireguard/clients');
        $this->line('sudo chmod -R 770 /etc/wireguard && sudo chown -R root:www-data /etc/wireguard');
        $this->line('sudo chmod u+s `which wg` `which wg-quick` `which ip` `which systemctl`');
        $this->line('');
        $this->warn('Ensure your security twice!');
        $this->warn('Do not allow another users on this VPN host and do not allow another significant daemons on it.');
        $this->line('');
    }

    protected function system($cmd, $errMsg, bool $fatal = false)
    {
        exec($cmd, $output, $ret);
        if ($ret) {
            if ($fatal) {
                $this->error($errMsg);
                die(1);
            }

            $this->warn($errMsg);
            return false;
        }

        if (count($output) == 1) {
            return $output[0];
        }

        return $output;
    }

    protected function verifyInterface(string $link)
    {
        exec('wg show interfaces', $output, $ret);
        if ($ret || empty($output)) {
            return false;
        }

        $interfaces = explode(' ', $output[0]);
        return in_array($link, $interfaces);
    }

    protected function readLink(string $link)
    {
        if (!$this->verifyInterface($link)) {
            $this->error("Interface does not exists: {$link}");
            die(1);
        }

        $public_key = $this->system("wg show {$link} public-key", "Can not retreive public key for {$link}.");
        $private_key = $this->system("wg show {$link} private-key", "Can not retreive private key for {$link}.");
        $listen_port = $this->system("wg show {$link} listen-port", "Can not retreive port number for {$link}.");
        $vpn_address = $this->system("ip address show {$link} | grep inet | awk '{print $2}'", "Can not retreive internal IP for {$link}.");
        if (empty($vpn_address)) {
            $vpn_address = "(none)";
        }

        $peers = [];
        $peers_psks = $this->system("wg show {$link} preshared-keys", "Can not retreive peers for {$link}.");
        if (is_string($peers_psks)) {
            $peers_psks = [ $peers_psks ];
        }
        foreach ($peers_psks as $peer_psk) {
            list ($peer, $psk) = preg_split('~\s+~', $peer_psk);
            $peers[$peer] = [
                'psk' => $psk,
            ];
        }

        $peers_ips = $this->system("wg show {$link} allowed-ips", "Can not retreive peers for {$link}.");
        if (is_string($peers_ips)) {
            $peers_ips = [ $peers_ips ];
        }
        foreach ($peers_ips as $peer_ip) {
            list ($peer, $ip) = preg_split('~\s+~', $peer_ip);
            $peers[$peer]['ip'] = $ip;
        }

        return (object) [
            'iface' => $link,
            'public_key' => $public_key,
            'private_key' => $private_key,
            'listen_port' => $listen_port,
            'vpn_address' => $vpn_address,
            'peers' => $peers,
        ];
    }

    protected function genPsk()
    {
        return $this->system("wg genpsk", "Can not generate PSK key.");
    }

    protected function genPrivKey()
    {
        return $this->system("wg genkey", "Can not generate Private Key.");
    }

    protected function genPubKey($priv)
    {
        $priv = escapeshellarg($priv);
        return $this->system("echo {$priv} | wg pubkey", "Can not generate Public Key.");
    }
}
