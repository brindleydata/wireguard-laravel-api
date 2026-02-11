<?php

namespace App\Services\Os;

use App\Services\ConfigBuilder;
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

    public function publicIpv4(string $ip_service): ?string
    {
        return $this->shell->tryRun('curl -4 -s --max-time 5 :url', ['url' => $ip_service]);
    }

    public function publicIpv6(string $ip_service): ?string
    {
        return $this->shell->tryRun('curl -6 -s --max-time 5 :url', ['url' => $ip_service]);
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
            $down = [];

            if ($forward) {
                $up[] = "nft add chain inet wg_%i forward '{ type filter hook forward priority 0; }'";
                $up[] = 'nft add rule inet wg_%i forward iifname "%i" accept';
                $up[] = 'nft add rule inet wg_%i forward oifname "%i" accept';
                $down[] = 'nft flush chain inet wg_%i forward 2>/dev/null';
                $down[] = 'nft delete chain inet wg_%i forward 2>/dev/null';
            }

            if ($nat) {
                $up[] = "nft add chain inet wg_%i postrouting '{ type nat hook postrouting priority 100; }'";
                $up[] = "nft add rule inet wg_%i postrouting oifname \"{$ifout}\" masquerade";
                $down[] = 'nft flush chain inet wg_%i postrouting 2>/dev/null';
                $down[] = 'nft delete chain inet wg_%i postrouting 2>/dev/null';
            }

            $down[] = 'nft delete table inet wg_%i 2>/dev/null';

            $lines[] = 'PostUp = '.implode('; ', $up);
            $lines[] = 'PostDown = '.implode('; ', $down);
        }

        return implode("\n", $lines);
    }

    public function enableForward(string $name): void
    {
        $table = "wg_{$name}";
        $this->shell->run('sudo nft add table inet :table', ['table' => $table]);
        $this->shell->run(
            "sudo nft add chain inet :table forward '{ type filter hook forward priority 0; }'",
            ['table' => $table],
        );
        $this->shell->run(
            'sudo nft add rule inet :table forward iifname :name accept',
            ['table' => $table, 'name' => $name],
        );
        $this->shell->run(
            'sudo nft add rule inet :table forward oifname :name accept',
            ['table' => $table, 'name' => $name],
        );
    }

    public function disableForward(string $name): void
    {
        $table = "wg_{$name}";
        $this->shell->tryRun('sudo nft flush chain inet :table forward', ['table' => $table]);
        $this->shell->tryRun('sudo nft delete chain inet :table forward', ['table' => $table]);
        $this->deleteTableIfEmpty($table);
    }

    public function enableNat(string $name, string $ifout): void
    {
        $table = "wg_{$name}";
        $this->shell->run('sudo nft add table inet :table', ['table' => $table]);
        $this->shell->run(
            "sudo nft add chain inet :table postrouting '{ type nat hook postrouting priority 100; }'",
            ['table' => $table],
        );
        $this->shell->run(
            'sudo nft add rule inet :table postrouting oifname :ifout masquerade',
            ['table' => $table, 'ifout' => $ifout],
        );
    }

    public function disableNat(string $name, string $ifout): void
    {
        $table = "wg_{$name}";
        $this->shell->tryRun('sudo nft flush chain inet :table postrouting', ['table' => $table]);
        $this->shell->tryRun('sudo nft delete chain inet :table postrouting', ['table' => $table]);
        $this->deleteTableIfEmpty($table);
    }

    public function writeConfig(string $name, string $content): void
    {
        $dir = $this->configPath();
        $path = "{$dir}/{$name}.conf";

        // /etc/wireguard requires sudo — write to temp then copy
        $tmp = tempnam(sys_get_temp_dir(), 'wg_');
        file_put_contents($tmp, $content."\n");
        chmod($tmp, 0600);

        $this->shell->run('sudo cp :tmp :path && sudo chmod 600 :path', ['tmp' => $tmp, 'path' => $path]);
        @unlink($tmp);
    }

    public function deleteConfig(string $name): void
    {
        $path = $this->configPath()."/{$name}.conf";
        $this->shell->tryRun('sudo rm -f :path', ['path' => $path]);
    }

    public function readConfig(string $name): ?string
    {
        $path = $this->configPath()."/{$name}.conf";

        // Try direct read first (may work if running as root)
        if (is_readable($path)) {
            return file_get_contents($path);
        }

        return $this->shell->tryRun('sudo cat :path', ['path' => $path]);
    }

    public function configExists(string $name): bool
    {
        $path = $this->configPath()."/{$name}.conf";
        if (file_exists($path)) {
            return true;
        }

        return $this->shell->tryRun('sudo test -f :path && echo 1', ['path' => $path]) === '1';
    }

    public function listConfigNames(): array
    {
        $output = $this->shell->tryRun('sudo ls :path', ['path' => $this->configPath()]);
        if ($output === null || $output === '') {
            return [];
        }

        $names = [];
        foreach (explode("\n", trim($output)) as $file) {
            if (str_ends_with($file, '.conf')) {
                $names[] = basename($file, '.conf');
            }
        }

        return $names;
    }

    public function parseConfig(string $name): ?array
    {
        $content = $this->readConfig($name);
        if ($content === null) {
            return null;
        }

        return ConfigBuilder::parseMetadata($content);
    }

    public function startInterface(string $name): void
    {
        $this->shell->run('sudo systemctl enable :unit && sudo systemctl start :unit', ['unit' => "wg-quick@{$name}"]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo systemctl stop :unit && sudo systemctl disable :unit', ['unit' => "wg-quick@{$name}"]);
    }

    public function writeClientConfig(string $link, string $key, string $content): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        $path = "{$dir}/{$key}.conf";

        $tmp = tempnam(sys_get_temp_dir(), 'wg_client_');
        file_put_contents($tmp, $content."\n");
        chmod($tmp, 0600);

        $this->shell->run('sudo mkdir -p :dir && sudo cp :tmp :path && sudo chmod 600 :path', [
            'dir' => $dir,
            'tmp' => $tmp,
            'path' => $path,
        ]);
        @unlink($tmp);
    }

    public function readClientConfig(string $link, string $key): ?string
    {
        $path = $this->configPath()."/clients/{$link}/{$key}.conf";

        if (is_readable($path)) {
            return file_get_contents($path);
        }

        return $this->shell->tryRun('sudo cat :path', ['path' => $path]);
    }

    public function deleteClientConfig(string $link, string $key): void
    {
        $path = $this->configPath()."/clients/{$link}/{$key}.conf";
        $this->shell->tryRun('sudo rm -f :path', ['path' => $path]);
    }

    public function deleteClientConfigDir(string $link): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        $this->shell->tryRun('sudo rm -rf :dir', ['dir' => $dir]);
    }

    protected function deleteTableIfEmpty(string $table): void
    {
        $output = $this->shell->tryRun('sudo nft list table inet :table', ['table' => $table]);
        if ($output === null) {
            return;
        }

        if (! str_contains($output, 'chain ')) {
            $this->shell->tryRun('sudo nft delete table inet :table', ['table' => $table]);
        }
    }
}
