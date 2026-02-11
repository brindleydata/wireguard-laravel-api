<?php

namespace App\Services\Os;

use App\Services\Shell;

class MacDriver implements OsDriver
{
    public function __construct(
        protected Shell $shell,
    ) {}

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

        $used = (int) (($active + $wired) * 4096 / 1024);
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

    public function configPath(): string
    {
        // Apple Silicon uses /opt/homebrew, Intel uses /usr/local
        $arm_path = '/opt/homebrew/etc/wireguard';
        $intel_path = '/usr/local/etc/wireguard';

        if (is_dir($arm_path)) {
            return $arm_path;
        }

        if (is_dir($intel_path)) {
            return $intel_path;
        }

        // Fallback based on architecture
        return php_uname('m') === 'arm64' ? $arm_path : $intel_path;
    }

    public function interfaceSection(string $address, string $privkey, int $port, string $ifout): string
    {
        $anchor = 'wg/%i';

        $post_up = implode('; ', [
            "echo \"nat on {$ifout} from {$address} to any -> ({$ifout})\" | pfctl -a \"{$anchor}\" -f -",
            'pfctl -e 2>/dev/null || true',
        ]);

        $post_down = "pfctl -a \"{$anchor}\" -F all 2>/dev/null || true";

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
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $path = "{$dir}/{$name}.conf";
        file_put_contents($path, $content."\n");
        chmod($path, 0600);
    }

    public function deleteConfig(string $name): void
    {
        $path = $this->configPath()."/{$name}.conf";
        if (file_exists($path)) {
            unlink($path);
        }
    }

    public function readConfig(string $name): ?string
    {
        $path = $this->configPath()."/{$name}.conf";
        if (! file_exists($path)) {
            return null;
        }

        return file_get_contents($path);
    }

    public function configExists(string $name): bool
    {
        return file_exists($this->configPath()."/{$name}.conf");
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
        $this->shell->run('sudo wg-quick up :name', ['name' => $name]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo wg-quick down :name', ['name' => $name]);
    }

    public function writeClientConfig(string $link, string $ip, string $content): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $path = "{$dir}/{$ip}.conf";
        file_put_contents($path, $content."\n");
        chmod($path, 0600);
    }

    public function readClientConfig(string $link, string $ip): ?string
    {
        $path = $this->configPath()."/clients/{$link}/{$ip}.conf";
        if (! file_exists($path)) {
            return null;
        }

        return file_get_contents($path);
    }

    public function deleteClientConfig(string $link, string $ip): void
    {
        $path = $this->configPath()."/clients/{$link}/{$ip}.conf";
        if (file_exists($path)) {
            unlink($path);
        }
    }

    public function deleteClientConfigDir(string $link): void
    {
        $dir = $this->configPath()."/clients/{$link}";
        if (! is_dir($dir)) {
            return;
        }

        $files = glob("{$dir}/*");
        foreach ($files as $file) {
            @unlink($file);
        }
        @rmdir($dir);
    }

    protected function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
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
