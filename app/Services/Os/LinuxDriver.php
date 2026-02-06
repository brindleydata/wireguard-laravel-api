<?php

namespace App\Services\Os;

use App\Services\Shell;

class LinuxDriver implements OsDriver
{
    public function __construct(
        protected Shell $shell,
    ) {}

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
        $free = 0;

        $meminfo = $this->shell->run('cat /proc/meminfo');
        foreach (explode("\n", $meminfo) as $line) {
            if (! str_contains($line, ':')) {
                continue;
            }
            [$name, $value] = preg_split('/:\s+/', $line);
            if ($name === 'MemTotal') {
                $total = (int) $value;
            } elseif ($name === 'MemFree') {
                $free = (int) $value;
            }

            if ($total && $free) {
                break;
            }
        }

        $usage = $total > 0 ? (int) round($free / $total * 100) : 0;

        return compact('total', 'free', 'usage');
    }

    public function disk(string $partition = '/'): array
    {
        $escaped = escapeshellarg($partition);
        $output = $this->shell->run("df {$escaped}");
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

    public function publicIp(string $ipService): string
    {
        $escaped = escapeshellarg($ipService);

        return $this->shell->run("curl -s --max-time 5 {$escaped}");
    }

    public function networkInterfaces(): array
    {
        $output = $this->shell->run('ip link show');
        $interfaces = [];
        foreach (explode("\n", $output) as $line) {
            if (preg_match('/^\d+: (?<iface>\w+):/', $line, $matches)) {
                $interfaces[] = $matches['iface'];
            }
        }

        return $interfaces;
    }

    public function interfaceAddress(string $ifname): ?string
    {
        $escaped = escapeshellarg($ifname);
        $output = $this->shell->tryRun("ip address show dev {$escaped}");
        if ($output === null) {
            return null;
        }

        if (preg_match('/inet (\d+\.\d+\.\d+\.\d+\/\d+)/', $output, $matches)) {
            return $matches[1];
        }

        return null;
    }

    public function configPath(): string
    {
        return '/etc/wireguard';
    }

    public function interfaceTemplate(string $address, string $privkey, int $port, string $ifout): string
    {
        return implode("\n", [
            '[Interface]',
            "Address = {$address}",
            'SaveConfig = true',
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
            "PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {$ifout} -j MASQUERADE;",
            "PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {$ifout} -j MASQUERADE;",
        ]);
    }

    public function startInterface(string $name): void
    {
        $escaped = escapeshellarg($name);
        $this->shell->run("sudo systemctl enable wg-quick@{$escaped}");
        $this->shell->run("sudo systemctl start wg-quick@{$escaped}");
    }

    public function stopInterface(string $name): void
    {
        $escaped = escapeshellarg($name);
        $this->shell->run("sudo systemctl stop wg-quick@{$escaped}");
        $this->shell->run("sudo systemctl disable wg-quick@{$escaped}");
    }
}
