<?php

namespace App\Models;

use App\Services\Host;
use App\Services\WireGuard;
use Illuminate\Support\Collection;

class Link
{
    public string $ifname;
    public string $address;
    public int $port;
    public string $privkey;
    public string $pubkey;
    public string $ifout;
    public Collection $subnets;

    public function __construct(
        private Host $host) {
    }

    /**
     * @throws Exception
     */
    public function getEndPoint(): string
    {
        $public_ip = $this->wg->cmd("curl --interface {$this->ifout} ifconfig.me");
        return $public_ip . ":" . $this->port;
    }

    /**
     * @throws Exception
     */
    public function save(): bool
    {
        if ($this->wg->interfaceExists($this->name, $wireguard_only = false))
            throw new Exception("Network adapter '{$this->name}' already exists.");

        if (!$this->wg->interfaceExists($this->ifout, $wireguard_only = false))
            throw new Exception("Output Network adapter '{$this->ifout}' is not exists.");

        if (empty($this->name))
            throw new Exception('Missed network adapter name.');

        if (empty($this->port))
            throw new Exception('Missed network adapter port number.');

        if (empty($this->ip))
            throw new Exception('Missed network adapter IP address.');

        if (empty($this->subnets))
            throw new Exception('Missed target subnets.');

        if (empty($this->ifout))
            throw new Exception('Missed output (masquerading) network adapter name.');

        try {
            System::shot("sudo systemctl stop wg-quick@{$this->name}");
            System::shot("sudo systemctl disable wg-quick@{$this->name}");
            System::shot("rm /etc/wireguard/{$this->name}.conf");
        } catch (Exception $ignore) {
            // no action needed
        }

        try {
            System::shot("echo '{$template}' | tee /etc/wireguard/{$this->name}.conf");
            System::shot("sudo systemctl enable wg-quick@{$this->name}");
            System::shot("sudo systemctl start wg-quick@{$this->name}");
        } catch (Exception $e) {
            try {
                System::shot("sudo systemctl stop wg-quick@{$this->name}");
                System::shot("sudo systemctl disable wg-quick@{$this->name}");
            } catch (Exception $ignore) {
                // do nothing
            }

            throw $e;
        }

        return true;
    }

    /**
     * @return bool
     * @throws Exception
     */
    public function delete(): bool
    {
        System::shot("sudo systemctl stop wg-quick@{$this->name}");
        System::shot("sudo systemctl disable wg-quick@{$this->name}");
        return true;
    }

    /**
     * @param array $data
     * @return Adapter
     * @throws Exception
     */
    public static function Create(array $data): Adapter
    {
        $name = strval($data['name'] ?? null);
        $port = intval($data['port'] ?? mt_rand(32767, 65535));
        $ifout = strval($data['ifout'] ?? 'ens5');
        $subnets = strval($data['subnets'] ?? null);
        $ip = strval($data['ip'] ?? null);

        if (!strpos($ip, '/')) {
            $ip .= "/24";
        }

        $interface = new Adapter(app()->get(WireGuard::class));
        $interface->name = $name;
        $interface->port = $port;
        $interface->ip = $ip;
        $interface->ifout = $ifout;
        $interface->subnets = $subnets;

        return $interface;
    }

    /**
     * @param string $name
     * @return Adapter
     * @throws Exception
     */
    public static function Read(string $name): Adapter
    {
        try {
            $privkey = System::shot("sudo wg show {$name} private-key");
        } catch (Exception $e) {
            throw new Exception("Could not find network adapter '{$name}'.");
        }

        $interface = new Adapter(app()->get(WireGuard::class), $privkey);
        $interface->name = $name;
        $interface->ip = System::shot("sudo ip address show dev {$name} | grep inet | awk '{print $2}'");
        $interface->port = System::shot("sudo wg show {$name} listen-port");
        $interface->ifout = System::shot("sudo /usr/sbin/iptables -t nat -L POSTROUTING -n -v | grep MASQUERADE | awk '{print $7}'");
        $interface->subnets = System::shot("cat /etc/wireguard/{$name}.conf | grep PostUp | awk '{print $23}'");

        return $interface;
    }
}
