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

    public function publicIp(string $ip_service): string
    {
        $escaped = escapeshellarg($ip_service);

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

    public function defaultOutboundInterface(): string
    {
        // "default via 192.168.1.1 dev eth0 ..."
        $output = $this->shell->run('ip route show default');
        if (preg_match('/dev\s+(\S+)/', $output, $matches)) {
            return $matches[1];
        }

        return 'eth0';
    }

    public function createInterface(string $name): string
    {
        $escaped = escapeshellarg($name);
        $result = $this->shell->tryRun("sudo ip link add dev {$escaped} type wireguard");

        if ($result === null) {
            $this->shell->run("sudo wireguard-go {$escaped}");
        }

        return $name;
    }

    public function destroyInterface(string $ifname): void
    {
        $escaped = escapeshellarg($ifname);
        $this->shell->run("sudo ip link delete dev {$escaped}");
    }

    public function assignAddress(string $ifname, string $address): void
    {
        $escaped_if = escapeshellarg($ifname);
        $escaped_addr = escapeshellarg($address);
        $this->shell->run("sudo ip address add {$escaped_addr} dev {$escaped_if}");
    }

    public function bringUp(string $ifname): void
    {
        $escaped = escapeshellarg($ifname);
        $this->shell->run("sudo ip link set {$escaped} up");
    }

    public function addNatRules(string $ifname, string $address, string $ifout): void
    {
        $escaped_if = escapeshellarg($ifname);
        $escaped_ifout = escapeshellarg($ifout);
        $comment = escapeshellarg("wg:{$ifname}");

        $this->shell->run(
            "sudo iptables -A FORWARD -i {$escaped_if} -j ACCEPT -m comment --comment {$comment}"
        );
        $this->shell->run(
            "sudo iptables -A FORWARD -o {$escaped_if} -j ACCEPT -m comment --comment {$comment}"
        );
        $this->shell->run(
            "sudo iptables -t nat -A POSTROUTING -o {$escaped_ifout} -j MASQUERADE -m comment --comment {$comment}"
        );
    }

    public function removeNatRules(string $ifname): void
    {
        $tag = "wg:{$ifname}";

        $this->removeTaggedRules('filter', 'FORWARD', $tag);
        $this->removeTaggedRules('nat', 'POSTROUTING', $tag);
    }

    public function isForwardingEnabled(): bool
    {
        $value = trim($this->shell->run('cat /proc/sys/net/ipv4/ip_forward'));

        return $value === '1';
    }

    public function enableForwarding(): void
    {
        $this->shell->run('sudo sysctl -w net.ipv4.ip_forward=1');
    }

    public function disableForwarding(): void
    {
        $this->shell->run('sudo sysctl -w net.ipv4.ip_forward=0');
    }

    protected function removeTaggedRules(string $table, string $chain, string $tag): void
    {
        $escaped_table = escapeshellarg($table);
        $output = $this->shell->tryRun("sudo iptables -t {$escaped_table} -S {$chain}");
        if ($output === null) {
            return;
        }

        foreach (explode("\n", $output) as $line) {
            $line = trim($line);
            if ($line === '' || ! str_contains($line, $tag)) {
                continue;
            }

            $delete_rule = preg_replace('/^-A\s+/', '-D ', $line);
            if ($delete_rule === $line) {
                continue;
            }

            $this->shell->tryRun("sudo iptables -t {$escaped_table} {$delete_rule}");
        }
    }
}
