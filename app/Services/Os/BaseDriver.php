<?php

namespace App\Services\Os;

use App\Exceptions\HelperException;
use App\Services\ConfigBuilder;
use App\Services\Shell;

/**
 * Everything privileged, shared by both drivers: it all goes through the root helper
 * (bin/wgla-helper, installed as config('wireguard.helper')), the one command sudoers allows.
 * The helper knows the OS-specific paths, lifecycle and firewall; contents go in on stdin.
 */
abstract class BaseDriver implements OsDriver
{
    /**
     * @param  string|null  $bundledHelperPath  The bin/wgla-helper this app ships. When given, the
     *                                          installed helper must be identical before it is used.
     */
    public function __construct(
        protected Shell $shell,
        protected string $helperPath = '/usr/local/sbin/wgla-helper',
        protected ?string $bundledHelperPath = null,
    ) {}

    /**
     * What wg-quick expands to [the link name, the OS interface] in a hook on this OS.
     *
     * @return array{0: string, 1: string}
     */
    abstract protected function hookPlaceholders(): array;

    public function publicIpv4(string $ip_service): ?string
    {
        return $this->publicIp($ip_service, '-4', FILTER_FLAG_IPV4);
    }

    public function publicIpv6(string $ip_service): ?string
    {
        return $this->publicIp($ip_service, '-6', FILTER_FLAG_IPV6);
    }

    /**
     * Only an address of the asked family counts: without real IPv6, `curl -6` can still get an
     * answer (e.g. DNS hands out IPv4-mapped ::ffff:a.b.c.d addresses, or NAT64), and the service
     * then reports the IPv4 address. Error pages and other junk don't count either.
     */
    protected function publicIp(string $ip_service, string $flag, int $family): ?string
    {
        $answer = trim((string) $this->shell->tryRun("curl {$flag} -s --max-time 5 :url", ['url' => $ip_service]));

        return filter_var($answer, FILTER_VALIDATE_IP, $family) !== false ? $answer : null;
    }

    // ─── WireGuard runtime state ────────────────────────────────────

    public function runningInterfaces(): array
    {
        $output = $this->tryHelper('interfaces');

        return $output === null || $output === '' ? [] : preg_split('/\s+/', $output);
    }

    public function interfaceDump(string $iface): string
    {
        return $this->helper('dump :iface', ['iface' => $iface]);
    }

    public function addPeer(string $iface, string $section): void
    {
        $this->helper('peer-add :iface', ['iface' => $iface], $section);
    }

    public function removePeer(string $iface, string $pubkey): void
    {
        $this->helper('peer-remove :iface :pubkey', ['iface' => $iface, 'pubkey' => $pubkey]);
    }

    public function setPeerAllowedIps(string $iface, string $pubkey, string $allowed_ips): void
    {
        $this->helper('peer-ips :iface :pubkey :ips', ['iface' => $iface, 'pubkey' => $pubkey, 'ips' => $allowed_ips]);
    }

    // ─── Link lifecycle ─────────────────────────────────────────────

    public function resolveInterface(string $link): string
    {
        return $this->tryHelper('resolve :name', ['name' => $link]) ?: $link;
    }

    public function startInterface(string $name): void
    {
        $this->helper('up :name', ['name' => $name]);
    }

    public function stopInterface(string $name): void
    {
        $this->helper('down :name', ['name' => $name]);
    }

    // ─── Link configs ───────────────────────────────────────────────

    public function interfaceSection(string $address, string $privkey, int $port, string $ifout, bool $forward = false, bool $nat = false): string
    {
        $lines = [
            '[Interface]',
            "Address = {$address}",
            "PrivateKey = {$privkey}",
            "ListenPort = {$port}",
        ];

        if ($forward || $nat) {
            [$link, $iface] = $this->hookPlaceholders();
            $lines[] = "PostUp = {$this->helperPath} firewall-up {$link} {$iface}";
            $lines[] = "PostDown = {$this->helperPath} firewall-down {$link}";
        }

        return implode("\n", $lines);
    }

    public function writeConfig(string $name, string $content): void
    {
        $this->helper('conf-write :name', ['name' => $name], $content."\n");
    }

    public function deleteConfig(string $name): void
    {
        $this->tryHelper('conf-delete :name', ['name' => $name]);
    }

    public function readConfig(string $name): ?string
    {
        return $this->tryHelper('conf-read :name', ['name' => $name]);
    }

    public function configExists(string $name): bool
    {
        return $this->readConfig($name) !== null;
    }

    public function listConfigNames(): array
    {
        $output = $this->tryHelper('conf-list');

        return $output === null || $output === '' ? [] : explode("\n", $output);
    }

    public function parseConfig(string $name): ?array
    {
        $content = $this->readConfig($name);

        return $content === null ? null : ConfigBuilder::parseMetadata($content);
    }

    // ─── Client configs ─────────────────────────────────────────────

    public function writeClientConfig(string $link, string $key, string $content): void
    {
        $this->helper('client-write :link :key', ['link' => $link, 'key' => $key], $content."\n");
    }

    public function readClientConfig(string $link, string $key): ?string
    {
        return $this->tryHelper('client-read :link :key', ['link' => $link, 'key' => $key]);
    }

    public function deleteClientConfig(string $link, string $key): void
    {
        $this->tryHelper('client-delete :link :key', ['link' => $link, 'key' => $key]);
    }

    public function deleteClientConfigDir(string $link): void
    {
        $this->tryHelper('client-delete-all :link', ['link' => $link]);
    }

    // ─── Firewall ───────────────────────────────────────────────────

    public function applyFirewall(string $link, string $iface): void
    {
        $this->helper('firewall-up :link :iface', ['link' => $link, 'iface' => $iface]);
    }

    public function clearFirewall(string $link): void
    {
        $this->tryHelper('firewall-down :link', ['link' => $link]);
    }

    // ─── Helper ─────────────────────────────────────────────────────

    public function helperStatus(): array
    {
        $state = $this->helperDrift()
            ?? ($this->shell->tryRun('sudo -n :helper version', ['helper' => $this->helperPath]) === null ? 'not-allowed' : 'ok');

        return [
            'state' => $state,
            'installed' => $this->helperVersion($this->helperPath),
            'bundled' => $this->bundledHelperPath === null ? null : $this->helperVersion($this->bundledHelperPath),
        ];
    }

    /**
     * Run a helper command as root. `sudo -n` fails at once when sudoers isn't set up, instead
     * of waiting for a password.
     */
    protected function helper(string $command, array $bindings = [], ?string $input = null): string
    {
        $this->assertHelperCurrent();

        return $this->shell->run("sudo -n :helper {$command}", ['helper' => $this->helperPath, ...$bindings], $input);
    }

    protected function tryHelper(string $command, array $bindings = [], ?string $input = null): ?string
    {
        // Throws rather than returning null: a stale helper must not look like "not found"
        $this->assertHelperCurrent();

        return $this->shell->tryRun("sudo -n :helper {$command}", ['helper' => $this->helperPath, ...$bindings], $input);
    }

    /**
     * Refuse to use a helper that isn't the one this app ships: after an app update without a
     * helper reinstall, it could reject the new app's configs or lack commands. Checked on every
     * call (hashing a small file) because Octane workers outlive updates.
     */
    protected function assertHelperCurrent(): void
    {
        $drift = $this->helperDrift();
        if ($drift === null) {
            return;
        }

        $fix = 'Install it with: php artisan wg:install';
        throw new HelperException($drift === 'missing'
            ? "The root helper is not installed at {$this->helperPath}. {$fix}"
            : sprintf(
                'The root helper at %s differs from the one this app ships (installed: v%s, app: v%s). %s',
                $this->helperPath,
                $this->helperVersion($this->helperPath) ?? '?',
                $this->helperVersion((string) $this->bundledHelperPath) ?? '?',
                $fix,
            ));
    }

    /**
     * `missing` or `outdated`, or null when the installed helper is the bundled one (or there is
     * no bundled copy to compare with). The installed helper is world-readable: no sudo needed.
     */
    protected function helperDrift(): ?string
    {
        if ($this->bundledHelperPath === null) {
            return null;
        }
        if (! is_file($this->helperPath)) {
            return 'missing';
        }

        return hash_file('sha256', $this->helperPath) === hash_file('sha256', $this->bundledHelperPath) ? null : 'outdated';
    }

    protected function helperVersion(string $path): ?string
    {
        $content = is_file($path) ? (string) file_get_contents($path) : '';

        return preg_match('/^VERSION=(\S+)$/m', $content, $m) ? $m[1] : null;
    }
}
