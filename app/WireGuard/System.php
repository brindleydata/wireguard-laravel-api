<?php

namespace App\WireGuard;

use function exec;

class System
{
    /**
     * @param $command
     * @return array
     * @throws Exception
     */
    public static function exec($command): array
    {
        exec($command, $output, $ret);
        if ($ret) {
            $output = implode("\n", $output);
            throw new Exception("System call failed.\nCommand: {$command}\n\n{$output}");
        }

        return $output;
    }

    /**
     * @param $command
     * @return string|null
     * @throws Exception
     */
    public static function shot($command): ?string
    {
        $ret = self::exec($command);

        return $ret[0] ?? null;
    }

    /**
     * Check if a given ip is in a network
     * @param string $ip IP to check in IPV4 format eg. 127.0.0.1
     * @param string $range IP/CIDR netmask eg. 127.0.0.0/24, also 127.0.0.1 is accepted and /32 assumed
     * @return boolean true if the ip is in this range / false if not.
     */
    public static function ip_in_range(string $ip, string $range): bool
    {
        if (!strpos($range, '/')) {
            $range .= '/32';
        }

        list($range, $netmask) = explode('/', $range, 2);
        $range_dec = ip2long($range);
        $ip_dec = ip2long($ip);
        $wildcard_dec = pow(2, (32 - $netmask)) - 1;
        $netmask_dec = ~$wildcard_dec;
        return (($ip_dec & $netmask_dec) == ($range_dec & $netmask_dec));
    }
}
