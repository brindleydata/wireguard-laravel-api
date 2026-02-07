<?php

namespace App\Services\Os;

use App\Services\Shell;
use RuntimeException;

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

    public function defaultOutboundInterface(): string
    {
        // "  interface: en0"
        $output = $this->shell->tryRun('route -n get default 2>/dev/null');
        if ($output !== null && preg_match('/interface:\s*(\S+)/', $output, $matches)) {
            return $matches[1];
        }

        return 'en0';
    }

    public function createInterface(string $name): string
    {
        // wireguard-go on macOS creates a utun device, prints the name to stderr
        $output = $this->shell->run('sudo wireguard-go utun 2>&1');

        // Output is like: "INFO: (utun4) 2024/01/01 ..."
        if (preg_match('/\((utun\d+)\)/', $output, $matches)) {
            return $matches[1];
        }

        throw new RuntimeException("Failed to parse utun name from wireguard-go output: {$output}");
    }

    public function destroyInterface(string $ifname): void
    {
        // Remove the socket file — wireguard-go watches it and exits automatically
        $socketPath = "/var/run/wireguard/{$ifname}.sock";
        if (file_exists($socketPath)) {
            $this->shell->tryRun('sudo rm '.escapeshellarg($socketPath));
            // Give wireguard-go a moment to notice and exit
            usleep(200_000);
        }

        // Fallback: if the process is still running, kill it
        $escaped = escapeshellarg($ifname);
        $pid = $this->shell->tryRun('pgrep -f '.escapeshellarg("wireguard-go.*{$ifname}"));
        if ($pid !== null && $pid !== '') {
            $this->shell->tryRun('sudo kill '.escapeshellarg(trim($pid)));
        }
    }

    public function assignAddress(string $ifname, string $address): void
    {
        // Parse IP and CIDR
        if (! str_contains($address, '/')) {
            $address .= '/24';
        }

        [$ip, $cidr] = explode('/', $address, 2);
        $netmask = $this->cidrToNetmask((int) $cidr);

        $escapedIf = escapeshellarg($ifname);
        $escapedIp = escapeshellarg($ip);
        $escapedMask = escapeshellarg($netmask);

        // On macOS, ifconfig for utun requires: ifconfig <utun> inet <ip> <ip> netmask <mask>
        $this->shell->run("sudo ifconfig {$escapedIf} inet {$escapedIp} {$escapedIp} netmask {$escapedMask}");

        // Add route for the subnet
        $network = long2ip(ip2long($ip) & ip2long($netmask));
        $escapedNet = escapeshellarg("{$network}/{$cidr}");
        $this->shell->tryRun("sudo route add -net {$escapedNet} -interface {$escapedIf}");
    }

    public function bringUp(string $ifname): void
    {
        // utun interfaces are auto-up on macOS — no-op
    }

    public function addNatRules(string $ifname, string $address, string $ifout): void
    {
        $anchor = "wg/{$ifname}";
        $escapedAnchor = escapeshellarg($anchor);

        // Build the NAT rule for this interface's anchor
        $natRule = "nat on {$ifout} from {$address} to any -> ({$ifout})";

        // Load the rule into the anchor
        $this->shell->run(
            'echo '.escapeshellarg($natRule)." | sudo pfctl -a {$escapedAnchor} -f -"
        );

        // Ensure pfctl is enabled (idempotent — already-enabled returns exit 0 from tryRun)
        $this->shell->tryRun('sudo pfctl -e 2>/dev/null');
    }

    public function removeNatRules(string $ifname): void
    {
        $anchor = "wg/{$ifname}";
        $escapedAnchor = escapeshellarg($anchor);

        // Flush only this interface's anchor — never disables pf globally
        $this->shell->tryRun("sudo pfctl -a {$escapedAnchor} -F all");
    }

    public function isForwardingEnabled(): bool
    {
        $value = trim($this->shell->run('sysctl -n net.inet.ip.forwarding'));

        return $value === '1';
    }

    public function enableForwarding(): void
    {
        $this->shell->run('sudo sysctl -w net.inet.ip.forwarding=1');
    }

    public function disableForwarding(): void
    {
        $this->shell->run('sudo sysctl -w net.inet.ip.forwarding=0');
    }

    protected function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
    }

    protected function cidrToNetmask(int $cidr): string
    {
        $mask = $cidr > 0 ? (~0 << (32 - $cidr)) & 0xFFFFFFFF : 0;

        return long2ip($mask);
    }
}
