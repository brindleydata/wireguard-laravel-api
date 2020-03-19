<?php

namespace App;

class WgService
{
    protected function _system($cmd)
    {
        exec($cmd, $output, $ret);
        if ($ret) {
            return false;
        }

        return $output;
    }

    public function genPsk(): ?string
    {
        return $this->_system("wg genpsk")[0] ?? null;
    }

    public function genPrivKey(): ?string
    {
        return $this->_system("wg genkey")[0] ?? null;
    }

    public function genPubKey($priv): ?string
    {
        $priv = escapeshellarg($priv);
        return $this->_system("echo {$priv} | wg pubkey")[0] ?? null;
    }

    public function getInterfaces(): array
    {
        $interfaces = $this->_system('wg show interfaces');
        return (!empty($interfaces[0])) ? explode(' ', $interfaces[0]) : [];
    }

    public function interfaceExists(string $link)
    {
        $interfaces = $this->getInterfaces();
        return in_array($link, $interfaces);
    }

    public function getInterface(string $link): ?WgInterface
    {
        if (!$this->interfaceExists($link)) {
            return null;
        }

        $public_key = $this->_system("wg show {$link} public-key")[0] ?? '(none)';
        $private_key = $this->_system("wg show {$link} private-key")[0] ?? '(none)';
        $listen_port = $this->_system("wg show {$link} listen-port")[0] ?? '(none)';
        $vpn_address = $this->_system("ip address show {$link} | grep inet | awk '{print $2}'")[0] ?? '(none)';

        $peers = [];
        $peers_ips = $this->_system("wg show {$link} allowed-ips");

        foreach ($peers_ips as $peer_ip) {
            list ($peer, $ip) = preg_split('~\s+~', $peer_ip);
            $ip = preg_replace('~/.+$~', '', $ip);
            $peer = $this->getPeer($link, $ip);
            if ($ip == '(none)') {
                continue;
            }

            if ($peer) {
                $peers []= $peer;
            }
        }

        return new WgInterface([
            'interface' => $link,
            'public_key' => $public_key,
            'private_key' => $private_key,
            'listen_port' => $listen_port,
            'vpn_address' => $vpn_address,
            'peers' => $peers,
        ]);
    }

    public function storeInterface(string $link, string $ip, string $ifout, int $port): bool
    {
        if ($this->interfaceExists($link)) {
            return false;
        }

        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $privkey = $this->genPrivKey();
        $pubkey = $this->genPubKey($privkey);
        $allowed_net = env('WIREGUARD_ALLOWED_NET');

        $template = <<<EOF
        [Interface]
        Address    = {$ip}/16
        SaveConfig = true
        PrivateKey = {$privkey}
        ListenPort = {$port}
        PostUp     = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -d {$allowed_net} -o {$ifout} -j MASQUERADE;
        PostDown   = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -d {$allowed_net} -o {$ifout} -j MASQUERADE;
        EOF;

        $this->_system("rm /etc/wireguard/{$link}.conf");
        $this->_system("chown -R www-data /etc/wireguard");

        $ret = $this->_system("echo '{$template}' > /etc/wireguard/{$link}.conf");
        if ($ret === false) {
            return false;
        }

        $this->_system("systemctl enable wg-quick@{$link}", "Could not enable {$link}");
        $this->_system("systemctl start wg-quick@{$link}", "Could not start {$link}");
        return true;
    }


    public function destroyInterface(string $link): bool
    {
        $iface = $this->getInterface($link);
        if (!$iface) {
            return false;
        }

        $this->_system("systemctl stop wg-quick@{$link}");
        $this->_system("systemctl disable wg-quick@{$link}");
        return true;
    }

    public function getPeer(string $link, string $ip): ?WgPeer
    {
        $config = [];
        $peer_config_file = @file("/etc/wireguard/clients/{$link}/{$ip}.conf");
        if (empty($peer_config_file)) {
            return null;
        }

        foreach ($peer_config_file as $line) {
            if (strpos($line, '=') === false) {
                continue;
            }

            $line = trim(rtrim($line));

            list($key, $value) = preg_split('~\s+=\s+~', $line);
            $key = str_replace([
                'PrivateKey',
                'PresharedKey',
                'Address',
                'PublicKey',
                'AllowedIPs',
                'Endpoint',
                'PersistentKeepalive',
                'DNS',
            ], [
                'private_key',
                'preshared_key',
                'vpn_address',
                'remote_public_key',
                'remote_allowed_ips',
                'remote_endpoint',
                'persistent_keepalive',
                'dns',
            ], $key);

            if (preg_match('~/32$~', $value)) {
                $value = preg_replace('~/32$~', '', $value);
            }

            $config[$key] = $value;
        }

        return new WgPeer($config);
    }

    public function storePeer(string $link, string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $iface = $this->getInterface($link);
        if (!$iface) {
            return false;
        }

        foreach ($iface->peers as $peer) {
            if ($peer->vpn_address == $ip) {
                return false;
            }
        }

        if ($ip == preg_replace('~/32$~', '', $iface->vpn_address)) {
            return false;
        }

        $privkey = $this->genPrivKey();
        $pubkey = $this->genPubKey($privkey);
        $psk = $this->genPsk();

        $cmd = "bash -c 'wg set {$link} peer {$pubkey} preshared-key <(echo {$psk}) allowed-ips {$ip}/32'";
        $ret = $this->_system($cmd);
        if ($ret === false) {
            return $ret;
        }

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

        $this->_system("mkdir -p /etc/wireguard/clients/{$link}");
        $this->_system("chown -R www-data /etc/wireguard");
        $ret = $this->_system("echo '{$template}' > '/etc/wireguard/clients/{$link}/{$ip}.conf'");
        if ($ret === false) {
            return $ret;
        }

        return true;
    }

    public function destroyPeer(string $link, string $ip): bool
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }

        $iface = $this->getInterface($link);
        if (!$iface) {
            return false;
        }

        $peer = false;
        foreach ($iface->peers as $src) {
            if ($src->vpn_address == $ip) {
                $peer = $src;
                break;
            }
        }

        if (!$peer) {
            return false;
        }

        $id = $this->genPubkey($peer->private_key);
        $this->_system("wg set {$link} peer {$id} remove");
        return true;
    }
}

