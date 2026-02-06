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
        // vm.loadavg returns "{ 1.23 4.56 7.89 }"
        preg_match('/\{\s*([\d.]+)/', $loadavg, $matches);
        $load = (float) ($matches[1] ?? 0);
        $usage = $cores > 0 ? (int) round($load / $cores * 100) : 0;

        return compact('cores', 'load', 'usage');
    }

    public function ram(): array
    {
        // Total RAM via sysctl (in bytes)
        $totalBytes = (int) $this->shell->run('sysctl -n hw.memsize');
        $total = (int) ($totalBytes / 1024); // convert to kB

        // Free pages via vm_stat
        $vmstat = $this->shell->run('vm_stat');
        $free = 0;
        if (preg_match('/Pages free:\s+(\d+)/', $vmstat, $matches)) {
            // vm_stat pages are 4096 bytes each
            $free = (int) ($matches[1] * 4096 / 1024); // convert to kB
        }

        $usage = $total > 0 ? (int) round($free / $total * 100) : 0;

        return compact('total', 'free', 'usage');
    }

    public function disk(string $partition = '/'): array
    {
        $escaped = escapeshellarg($partition);
        $output = $this->shell->run("df -k {$escaped}");
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
        $output = $this->shell->run('ifconfig -l');

        return preg_split('/\s+/', trim($output));
    }

    public function interfaceAddress(string $ifname): ?string
    {
        $escaped = escapeshellarg($ifname);
        $output = $this->shell->tryRun("ifconfig {$escaped}");
        if ($output === null) {
            return null;
        }

        // ifconfig on macOS shows: inet 10.0.0.1 netmask 0xffffff00
        if (preg_match('/inet (\d+\.\d+\.\d+\.\d+).*netmask (0x[0-9a-f]+)/', $output, $matches)) {
            $ip = $matches[1];
            $mask = $this->hexMaskToCidr($matches[2]);

            return "{$ip}/{$mask}";
        }

        return null;
    }

    public function configPath(): string
    {
        // Homebrew on Apple Silicon vs Intel
        if (is_dir('/opt/homebrew/etc/wireguard')) {
            return '/opt/homebrew/etc/wireguard';
        }

        if (is_dir('/usr/local/etc/wireguard')) {
            return '/usr/local/etc/wireguard';
        }

        // Default: create in homebrew location
        return PHP_OS_FAMILY === 'Darwin' && php_uname('m') === 'arm64'
            ? '/opt/homebrew/etc/wireguard'
            : '/usr/local/etc/wireguard';
    }

    public function interfaceTemplate(string $address, string $privkey, int $port, string $ifout): string
    {
        return implode("\n", [
            '[Interface]',
            "Address = {$address}",
            'SaveConfig = true',
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
            "PostUp = sysctl -w net.inet.ip.forwarding=1; pfctl -e; echo \"nat on {$ifout} from {$address} to any -> ({$ifout})\" | pfctl -f -",
            'PostDown = pfctl -d',
        ]);
    }

    public function startInterface(string $name): void
    {
        $escaped = escapeshellarg($name);
        $this->shell->run("sudo wg-quick up {$escaped}");
    }

    public function stopInterface(string $name): void
    {
        $escaped = escapeshellarg($name);
        $this->shell->run("sudo wg-quick down {$escaped}");
    }

    private function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
    }
}
