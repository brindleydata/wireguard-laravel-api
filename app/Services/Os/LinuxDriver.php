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

    public function interfaceSection(string $address, string $privkey, int $port, string $ifout): string
    {
        $comment = 'wg:%i';

        $post_up = implode('; ', [
            "iptables -A FORWARD -i %i -j ACCEPT -m comment --comment \"{$comment}\"",
            "iptables -A FORWARD -o %i -j ACCEPT -m comment --comment \"{$comment}\"",
            "iptables -t nat -A POSTROUTING -o {$ifout} -j MASQUERADE -m comment --comment \"{$comment}\"",
        ]);

        $post_down = implode('; ', [
            "iptables -D FORWARD -i %i -j ACCEPT -m comment --comment \"{$comment}\"",
            "iptables -D FORWARD -o %i -j ACCEPT -m comment --comment \"{$comment}\"",
            "iptables -t nat -D POSTROUTING -o {$ifout} -j MASQUERADE -m comment --comment \"{$comment}\"",
        ]);

        $lines = [
            '[Interface]',
            "Address = {$address}",
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
            "PostUp = {$post_up}",
            "PostDown = {$post_down}",
        ];

        return implode("\n", $lines);
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

        return file_exists($path);
    }

    public function parseConfig(string $name): ?array
    {
        $content = $this->readConfig($name);
        if ($content === null) {
            return null;
        }

        return $this->parseMetadataComments($content);
    }

    public function startInterface(string $name): void
    {
        $this->shell->run('sudo systemctl enable :unit && sudo systemctl start :unit', ['unit' => "wg-quick@{$name}"]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo systemctl stop :unit && sudo systemctl disable :unit', ['unit' => "wg-quick@{$name}"]);
    }

    public function writeClientConfig(string $link, string $ip, string $content): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        $path = "{$dir}/{$ip}.conf";

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

    public function readClientConfig(string $link, string $ip): ?string
    {
        $path = $this->configPath()."/clients/{$link}/{$ip}.conf";

        if (is_readable($path)) {
            return file_get_contents($path);
        }

        return $this->shell->tryRun('sudo cat :path', ['path' => $path]);
    }

    public function deleteClientConfig(string $link, string $ip): void
    {
        $path = $this->configPath()."/clients/{$link}/{$ip}.conf";
        $this->shell->tryRun('sudo rm -f :path', ['path' => $path]);
    }

    public function deleteClientConfigDir(string $link): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        $this->shell->tryRun('sudo rm -rf :dir', ['dir' => $dir]);
    }

    protected function parseMetadataComments(string $content): array
    {
        $metadata = [];
        foreach (explode("\n", $content) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] !== '#') {
                break;
            }
            if (preg_match('/^#\s*(\w+)\s*=\s*(.+)$/', $line, $matches)) {
                $metadata[trim($matches[1])] = trim($matches[2]);
            }
        }

        return $metadata;
    }
}
