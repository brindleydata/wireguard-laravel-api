<?php

namespace App\Services;

use RuntimeException;

class IpAllocator
{
    public function findAvailableIp(string $interface_address, array $existing_peers): string
    {
        if (! str_contains($interface_address, '/')) {
            throw new RuntimeException("Interface address must include CIDR notation: {$interface_address}");
        }

        [$network_ip, $mask] = explode('/', $interface_address, 2);
        $mask = (int) $mask;

        $network_long = ip2long($network_ip);
        $host_bits = 32 - $mask;
        $network_start = $network_long & ((-1 << $host_bits) & 0xFFFFFFFF);
        $network_end = $network_start | ((1 << $host_bits) - 1);

        // Collect all used IPs (interface address + existing peers)
        $used = [];
        $used[ip2long($network_ip)] = true;
        $used[$network_start] = true;       // network address
        $used[$network_end] = true;         // broadcast address

        foreach ($existing_peers as $peer) {
            $peer_ip = explode('/', $peer->allowed_ips, 2)[0];
            $used[ip2long($peer_ip)] = true;
        }

        // Find first available host
        for ($ip = $network_start + 1; $ip < $network_end; $ip++) {
            if (! isset($used[$ip])) {
                return long2ip($ip);
            }
        }

        throw new RuntimeException('No available IP addresses in subnet.');
    }
}
