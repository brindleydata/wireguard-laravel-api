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
    */
}

