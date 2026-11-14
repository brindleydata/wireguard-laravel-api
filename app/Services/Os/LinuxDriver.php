<?php

namespace App\Services\Os;

class LinuxDriver extends BaseDriver
{
    public function cpu(): array
    {
        $cores = (int) $this->shell->run('nproc');
        $loadavg = $this->shell->run('cat /proc/loadavg');
        $load = (float) preg_replace('/\s.+/', '', $loadavg);
        $usage = $cores > 0 ? (int) round($load / $cores * 100) : 0;

        return compact('cores', 'load', 'usage');
    }

    public function ram(): array
    {
        $total = 0;
        $available = 0;

        $meminfo = $this->shell->run('cat /proc/meminfo');
        foreach (explode("\n", $meminfo) as $line) {
            if (! str_contains($line, ':')) {
                continue;
            }
            [$name, $value] = preg_split('/:\s+/', $line);
            if ($name === 'MemTotal') {
                $total = (int) $value;
            } elseif ($name === 'MemAvailable') {
                $available = (int) $value;
            }

            if ($total && $available) {
                break;
            }
        }

        $free = $available;
        $usage = $total > 0 ? (int) round(($total - $free) / $total * 100) : 0;

        return compact('total', 'free', 'usage');
    }

    public function disk(string $partition = '/'): array
    {
        $output = $this->shell->run('df :partition', ['partition' => $partition]);
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
        $output = $this->shell->run('ip link show');
        $interfaces = [];
        foreach (explode("\n", $output) as $line) {
            // e.g. "2: eth0: <...>", "5: eth0@if6: <...>" (containers), "9: br-1a2b: <...>", "4: eth0.100@eth0: <...>"
            if (preg_match('/^\d+:\s+(?<iface>[^:@\s]+)(@\S+)?:/', $line, $matches)) {
                $interfaces[] = $matches['iface'];
            }
        }

        return $interfaces;
    }

    public function interfaceAddress(string $ifname): ?string
    {
        $output = $this->shell->tryRun('ip address show dev :ifname', ['ifname' => $ifname]);
        if ($output === null) {
            return null;
        }

        if (preg_match('/inet (\d+\.\d+\.\d+\.\d+\/\d+)/', $output, $matches)) {
            return $matches[1];
        }

        return null;
    }

    public function defaultOutboundInterface(): string
    {
        $output = $this->shell->run('ip route show default');
        if (preg_match('/dev\s+(\S+)/', $output, $matches)) {
            return $matches[1];
        }

        return 'eth0';
    }

    public function ownAddresses(): array
    {
        // "2: eth0    inet 192.0.2.10/24 brd …", "2: eth0    inet6 2001:db8::10/64 scope global …"
        preg_match_all('/\binet6? ([0-9A-Fa-f.:]+)\//', $this->shell->run('ip -o address show'), $addresses);
        preg_match_all('/\bvia ([0-9A-Fa-f.:]+)/', (string) $this->shell->tryRun('ip route show default'), $gateways);

        return array_values(array_unique([...$addresses[1], ...$gateways[1]]));
    }

    public function resolveInterface(string $link): string
    {
        // A Linux link runs as an interface of the same name; no helper call needed
        return $link;
    }

    protected function hookPlaceholders(): array
    {
        // wg-quick on Linux only expands %i (the interface, named after the link)
        return ['%i', '%i'];
    }
}
