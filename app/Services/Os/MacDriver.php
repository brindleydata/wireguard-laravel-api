<?php

namespace App\Services\Os;

use App\Services\IpAllocator;

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

    public function resolveInterface(string $link): string
    {
        // Written by wireguard-go (mode 0400, so it needs sudo) and removed by `wg-quick down`
        $real = $this->shell->tryRun('sudo cat :path', ['path' => "/var/run/wireguard/{$link}.name"]);

        return $real !== null && preg_match('/^utun\d+$/', $real) ? $real : $link;
    }

    /**
     * Rules live in the pf anchor `wg/<link>`. In wg-quick hooks on macOS `%i` expands to the
     * real utunN and `%I` to the link name, so the anchor uses `%I` (matching applyFirewall()
     * and clearFirewall()) while the rules use `%i`.
     */
    public function interfaceSection(string $address, string $privkey, int $port, string $ifout, bool $forward = false, bool $nat = false): string
    {
        $lines = [
            '[Interface]',
            "Address = {$address}",
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
        ];

        $rules = $this->firewallRules('%i', $address, $ifout, $forward, $nat);
        if ($rules !== []) {
            // A wg-quick value can't span lines, so printf emits one rule per line for pfctl.
            // `&&` makes a rejected ruleset fail `wg-quick up` instead of passing silently.
            $printf = "printf '%s\\n' ".implode(' ', array_map('escapeshellarg', $rules));
            $lines[] = "PostUp = {$printf} | pfctl -a 'wg/%I' -f - && { pfctl -e 2>/dev/null || true; }";
            $lines[] = "PostDown = pfctl -a 'wg/%I' -F all 2>/dev/null || true";
        }

        return implode("\n", $lines);
    }

    public function applyFirewall(string $link, string $iface, string $address, string $ifout, bool $forward, bool $nat): void
    {
        $rules = $this->firewallRules($iface, $address, $ifout, $forward, $nat);
        if ($rules === []) {
            $this->clearFirewall($link);

            return;
        }

        // Loading a ruleset into an anchor replaces everything previously in it
        $this->shell->run('sudo pfctl -a :anchor -f -', ['anchor' => "wg/{$link}"], implode("\n", $rules)."\n");
        $this->shell->tryRun('sudo pfctl -e');
    }

    public function clearFirewall(string $link): void
    {
        $this->shell->tryRun('sudo pfctl -a :anchor -F all', ['anchor' => "wg/{$link}"]);
    }

    public function startInterface(string $name): void
    {
        $this->shell->run('sudo wg-quick up :name', ['name' => $name]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo wg-quick down :name', ['name' => $name]);
    }

    /**
     * pf rejects a ruleset whose translation (nat) rules come after filter (pass) rules.
     */
    protected function firewallRules(string $iface, string $address, string $ifout, bool $forward, bool $nat): array
    {
        $rules = [];

        if ($nat) {
            $network = IpAllocator::networkCidr($address);
            $rules[] = "nat on {$ifout} from {$network} to any -> ({$ifout})";
        }

        if ($forward) {
            $rules[] = "pass in on {$iface} all";
            $rules[] = "pass out on {$iface} all";
        }

        return $rules;
    }

    protected function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
    }
}
