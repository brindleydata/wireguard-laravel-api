<?php

namespace App\Services\Os;

use App\Services\ConfigBuilder;
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

    public function interfaceSection(string $address, string $privkey, int $port, string $ifout, bool $forward = false, bool $nat = false): string
    {
        $anchor = 'wg/%i';

        $lines = [
            '[Interface]',
            "Address = {$address}",
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
        ];

        if ($forward || $nat) {
            $rules = [];
            if ($forward) {
                $rules[] = 'pass in on %i all';
                $rules[] = 'pass out on %i all';
            }
            if ($nat) {
                $rules[] = "nat on {$ifout} from {$address} to any -> ({$ifout})";
            }

            $post_up = 'echo "'.implode("\n", $rules)."\" | pfctl -a \"{$anchor}\" -f -; pfctl -e 2>/dev/null || true";
            $post_down = "pfctl -a \"{$anchor}\" -F all 2>/dev/null || true";

            $lines[] = "PostUp = {$post_up}";
            $lines[] = "PostDown = {$post_down}";
        }

        return implode("\n", $lines);
    }

    public function enableForward(string $name): void
    {
        $anchor = "wg/{$name}";
        $rules = $this->getCurrentAnchorRules($anchor);
        $rules[] = "pass in on {$name} all";
        $rules[] = "pass out on {$name} all";
        $this->loadAnchorRules($anchor, $rules);
    }

    public function disableForward(string $name): void
    {
        $anchor = "wg/{$name}";
        $rules = $this->getCurrentAnchorRules($anchor);
        $rules = array_values(array_filter($rules, fn (string $r) => ! str_starts_with($r, 'pass ')));
        $this->loadAnchorRules($anchor, $rules);
    }

    public function enableNat(string $name, string $ifout): void
    {
        $anchor = "wg/{$name}";
        $address = $this->interfaceAddress($name) ?? '0.0.0.0/0';
        $rules = $this->getCurrentAnchorRules($anchor);
        $rules[] = "nat on {$ifout} from {$address} to any -> ({$ifout})";
        $this->loadAnchorRules($anchor, $rules);
    }

    public function disableNat(string $name, string $ifout): void
    {
        $anchor = "wg/{$name}";
        $rules = $this->getCurrentAnchorRules($anchor);
        $rules = array_values(array_filter($rules, fn (string $r) => ! str_starts_with($r, 'nat ')));
        $this->loadAnchorRules($anchor, $rules);
    }

    protected function getCurrentAnchorRules(string $anchor): array
    {
        $output = $this->shell->tryRun('sudo pfctl -a :anchor -s rules 2>/dev/null', ['anchor' => $anchor]);
        $nat = $this->shell->tryRun('sudo pfctl -a :anchor -s nat 2>/dev/null', ['anchor' => $anchor]);

        $rules = [];
        foreach ([$nat, $output] as $block) {
            if ($block !== null && trim($block) !== '') {
                foreach (explode("\n", trim($block)) as $line) {
                    $line = trim($line);
                    if ($line !== '') {
                        $rules[] = $line;
                    }
                }
            }
        }

        return $rules;
    }

    protected function loadAnchorRules(string $anchor, array $rules): void
    {
        if ($rules === []) {
            $this->shell->tryRun('sudo pfctl -a :anchor -F all 2>/dev/null', ['anchor' => $anchor]);

            return;
        }

        $content = implode("\n", $rules);
        $tmp = tempnam(sys_get_temp_dir(), 'pfctl_');
        file_put_contents($tmp, $content."\n");

        try {
            $this->shell->run('sudo pfctl -a :anchor -f :tmp', ['anchor' => $anchor, 'tmp' => $tmp]);
            $this->shell->tryRun('sudo pfctl -e 2>/dev/null');
        } finally {
            @unlink($tmp);
        }
    }

    public function writeConfig(string $name, string $content): void
    {
        $dir = $this->configPath();
        $path = "{$dir}/{$name}.conf";

        $tmp = tempnam(sys_get_temp_dir(), 'wg_');
        file_put_contents($tmp, $content."\n");
        chmod($tmp, 0600);

        $this->shell->run('sudo mkdir -p :dir && sudo cp :tmp :path && sudo chmod 600 :path', [
            'dir' => $dir,
            'tmp' => $tmp,
            'path' => $path,
        ]);
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

        return $this->shell->tryRun('sudo cat :path', ['path' => $path]);
    }

    public function configExists(string $name): bool
    {
        $path = $this->configPath()."/{$name}.conf";

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
        $this->shell->run('sudo wg-quick up :name', ['name' => $name]);
    }

    public function stopInterface(string $name): void
    {
        $this->shell->run('sudo wg-quick down :name', ['name' => $name]);
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

    protected function hexMaskToCidr(string $hex): int
    {
        $decimal = hexdec(ltrim($hex, '0x'));
        $binary = decbin($decimal);

        return substr_count($binary, '1');
    }
}
