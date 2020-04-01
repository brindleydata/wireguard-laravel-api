<?php

namespace App\WireGuard;

class Service
{
    protected $config;
    protected $os;

    /**
     * Service constructor.
     * @param $config
     * @throws Exception
     */
    public function __construct($config)
    {
        $this->config = $config;
        $this->os = System::shot('uname');
        if ($this->os !== 'Linux') {
            throw new Exception('The only operating system supported is Linux.');
        }
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getStatus(): array
    {
        $cpu_cores = (int) System::shot('cat /proc/cpuinfo | grep processor | wc -l');
        $cpu_load = (float) preg_replace('~\s.+~', '', System::shot('cat /proc/loadavg'));
        $cpu_usage = round(($cpu_load / $cpu_cores) * 100);

        $ram_free = 0;
        $ram_total = 0;
        foreach (System::exec('cat /proc/meminfo') as $line) {
            list($name, $value) = preg_split('~:\s+~', $line);
            if ($name == 'MemTotal') {
                $ram_total = (int) $value;
            } else if ($name == 'MemFree') {
                $ram_free = (int) $value;
            }
        }

        list($disk_partition, $disk_size, , $disk_free, $disk_usage, ) = preg_split('~\s+~', System::exec('df /')[1]);

        return [
            'cpu' => [
                'cores' => $cpu_cores,
                'load' => $cpu_load,
                'usage' => $cpu_usage,
            ],

            'ram' => [
                'total' => $ram_total,
                'free' => $ram_free,
                'usage' => round(($ram_free / $ram_total) * 100),
            ],

            'disk' => [
                'partition' => $disk_partition,
                'size' => (int) $disk_size,
                'free' => (int) $disk_free,
                'usage' => (int) preg_replace('~\s*%~', '', $disk_usage),
            ],
        ];
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getInterfaces(): array
    {
        $interfaces = System::shot('wg show interfaces');
        return $interfaces ? explode(' ', $interfaces) : [];
    }

    /**
     * @param string $name
     * @param bool $wireguard_only
     * @return bool
     * @throws Exception
     */
    public function interfaceExists(string $name, bool $wireguard_only = true): bool
    {
        if ($wireguard_only) {
            return in_array($name, $this->getInterfaces());
        }

        $name = escapeshellarg($name);
        try {
            System::shot("ip link show {$name}");
        } catch (\Throwable $e) {
            return false;
        }

        return true;
    }

    /**
     * @return string
     * @throws Exception
     */
    public function genPsk(): string
    {
        return System::shot('wg genpsk');
    }

    /**
     * @return string
     * @throws Exception
     */
    public function genPrivKey(): string
    {
        return System::shot('wg genkey');
    }

    /**
     * @param string $privKey
     * @return string
     * @throws Exception
     */
    public function genPubKey(string $privKey): string
    {
        $privKey = escapeshellarg($privKey);
        return System::shot("echo {$privKey} | wg pubkey");
    }


    /*
    public function getInterface(string $name): ?Adapter
    {
        if (!$this->interfaceExists($name)) {
            return null;
        }

        $name = escapeshellarg($name);
        $public_key = System::shot("wg show {$name} public-key") ?? '(none)';
        $private_key = System::shot("wg show {$name} private-key") ?? '(none)';
        $listen_port = System::shot("wg show {$name} listen-port") ?? '(none)';
        $vpn_address = System::shot("ip address show {$name} | grep inet | awk '{print $2}'") ?? '(none)';

        $peers = [];
        $peers_ips = $this->_system("wg show {$name} allowed-ips");

        foreach ($peers_ips as $peer_ip) {
            list (, $ip) = preg_split('~\s+~', $peer_ip);
            $ip = preg_replace('~/.+$~', '', $ip);
            $peer = $this->getPeer($name, $ip);
            if ($ip == '(none)') {
                continue;
            }

            if ($peer) {
                $peers []= $peer;
            }
        }

        return new Adapter([
            'interface' => $name,
            'public_key' => $public_key,
            'private_key' => $private_key,
            'listen_port' => $listen_port,
            'vpn_address' => $vpn_address,
            'peers' => $peers,
        ]);
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
    */
}

