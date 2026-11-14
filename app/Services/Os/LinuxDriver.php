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

    public function configPath(): string
    {
        return '/etc/wireguard';
    }

    public function resolveInterface(string $link): string
    {
        return $link;
    }

    /**
     * Each link owns one nftables table, `inet wg_<link>`, so its rules can be dropped without
     * touching anything else. Must stay in sync with applyFirewall().
     */
    public function interfaceSection(string $address, string $privkey, int $port, string $ifout, bool $forward = false, bool $nat = false): string
    {
        $lines = [
            '[Interface]',
            "Address = {$address}",
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
        ];

        if ($forward || $nat) {
            $up = ['nft add table inet wg_%i'];

            if ($forward) {
                $up[] = "nft add chain inet wg_%i forward '{ type filter hook forward priority 0; }'";
                $up[] = 'nft add rule inet wg_%i forward iifname "%i" accept';
                $up[] = 'nft add rule inet wg_%i forward oifname "%i" accept';
            }

            if ($nat) {
                $up[] = "nft add chain inet wg_%i postrouting '{ type nat hook postrouting priority 100; }'";
                $up[] = "nft add rule inet wg_%i postrouting oifname \"{$ifout}\" masquerade";
            }

            $lines[] = 'PostUp = '.implode('; ', $up);
            // `|| true`: the service may already have cleared the table, and a failing hook would fail `wg-quick down`
            $lines[] = 'PostDown = nft delete table inet wg_%i 2>/dev/null || true';
        }

        return implode("\n", $lines);
    }

    public function applyFirewall(string $link, string $iface, string $address, string $ifout, bool $forward, bool $nat): void
    {
        $this->clearFirewall($link);

        if (! $forward && ! $nat) {
            return;
        }

        $table = "wg_{$link}";
        $this->shell->run('sudo nft add table inet :table', ['table' => $table]);

        if ($forward) {
            $this->shell->run("sudo nft add chain inet :table forward '{ type filter hook forward priority 0; }'", ['table' => $table]);
            $this->shell->run('sudo nft add rule inet :table forward iifname :iface accept', ['table' => $table, 'iface' => $iface]);
            $this->shell->run('sudo nft add rule inet :table forward oifname :iface accept', ['table' => $table, 'iface' => $iface]);
        }

        if ($nat) {
            $this->shell->run("sudo nft add chain inet :table postrouting '{ type nat hook postrouting priority 100; }'", ['table' => $table]);
            $this->shell->run('sudo nft add rule inet :table postrouting oifname :ifout masquerade', ['table' => $table, 'ifout' => $ifout]);
        }
    }

    public function clearFirewall(string $link): void
    {
        $this->shell->tryRun('sudo nft delete table inet :table', ['table' => "wg_{$link}"]);
    }

    public function startInterface(string $name): void
    {
        $this->shell->run('sudo systemctl enable :unit && sudo systemctl start :unit', ['unit' => "wg-quick@{$name}"]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo systemctl stop :unit && sudo systemctl disable :unit', ['unit' => "wg-quick@{$name}"]);
    }
}
