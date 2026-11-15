<?php

namespace App\Services\Os;

class MacDriver extends BaseDriver
{
    public function cpu(): array
    {
        $cores = (int) $this->shell->run('sysctl -n hw.ncpu');
        $loadavg = $this->shell->run('sysctl -n vm.loadavg');
        preg_match('/\{\s*([\d.]+)/', $loadavg, $matches);
        $load = (float) ($matches[1] ?? 0);
        $usage = $cores > 0 ? (int) round($load / $cores * 100) : 0;

        return compact('cores', 'load', 'usage');
    }

    public function ram(): array
    {
        $total_bytes = (int) $this->shell->run('sysctl -n hw.memsize');
        $total = (int) ($total_bytes / 1024);

        $vmstat = $this->shell->run('vm_stat');
        $active = 0;
        $wired = 0;
        if (preg_match('/Pages active:\s+(\d+)/', $vmstat, $matches)) {
            $active = (int) $matches[1];
        }
        if (preg_match('/Pages wired down:\s+(\d+)/', $vmstat, $matches)) {
            $wired = (int) $matches[1];
        }

        // 16384 on Apple Silicon, 4096 on Intel
        $page_size = preg_match('/page size of (\d+) bytes/', $vmstat, $matches) ? (int) $matches[1] : 4096;
        $used = (int) (($active + $wired) * $page_size / 1024);
        $free = $total - $used;
        $usage = $total > 0 ? (int) round($used / $total * 100) : 0;

        return compact('total', 'free', 'usage');
    }

    public function disk(string $partition = '/'): array
    {
        $output = $this->shell->run('df -k :partition', ['partition' => $partition]);
        $lines = explode("\n", $output);
        if (count($lines) < 2) {
            return ['partition' => $partition, 'size' => 0, 'free' => 0, 'usage' => 0];
        }

        $parts = preg_split('/\s+/', $lines[1]);

        return [
            'partition' => $parts[0] ?? $partition,
            'size' => (int) ($parts[1] ?? 0),
            'free' => (int) ($parts[3] ?? 0),
            'usage' => (int) preg_replace('/\s*%/', '', $parts[4] ?? '0'),
        ];
    }

    public function networkInterfaces(): array
    {
        $output = $this->shell->run('ifconfig -l');

        return preg_split('/\s+/', trim($output));
    }

    public function interfaceAddress(string $ifname): ?string
    {
        $output = $this->shell->tryRun('ifconfig :ifname', ['ifname' => $ifname]);
        if ($output === null) {
            return null;
        }

        if (preg_match('/inet (\d+\.\d+\.\d+\.\d+).*netmask (0x[0-9a-f]+)/', $output, $matches)) {
            $ip = $matches[1];
            $mask = $this->hexMaskToCidr($matches[2]);

            return "{$ip}/{$mask}";
        }

        return null;
    }

    public function defaultOutboundInterface(): string
    {
        $output = $this->shell->tryRun('route -n get default 2>/dev/null');
        if ($output !== null && preg_match('/interface:\s*(\S+)/', $output, $matches)) {
            return $matches[1];
        }

        return 'en0';
    }

    public function ownAddresses(): array
    {
        // "\tinet 192.0.2.10 netmask 0xffffff00 …", "\tinet6 fe80::1%lo0 prefixlen 64 …"
        preg_match_all('/\binet6? ([0-9A-Fa-f.:]+)/', $this->shell->run('ifconfig'), $addresses);
        preg_match_all('/gateway:\s*([0-9A-Fa-f.:]+)/', (string) $this->shell->tryRun('route -n get default 2>/dev/null'), $gateways);

        return array_values(array_unique([...$addresses[1], ...array_filter($gateways[1], fn (string $gateway) => filter_var($gateway, FILTER_VALIDATE_IP) !== false)]));
    }

    protected function hookPlaceholders(): array
    {
        // wg-quick on macOS expands %I to the link name and %i to the real utunN
        return ['%I', '%i'];
    }

    protected function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
    }
}
