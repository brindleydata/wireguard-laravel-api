<?php

namespace Tests\Fakes;

use LogicException;

/**
 * An in-memory host behind FakeShell. It plays the root helper's commands (bin/wgla-helper,
 * whose own behaviour is covered by HelperTest) plus the unprivileged system tools:
 *
 * - Linux: `up` enables + starts wg-quick@<link>, which runs as an interface named after the link.
 * - macOS: `up` runs wg-quick, which creates the next free utunN and records it (`resolve`).
 *
 * Starting a link rejects config lines wg-quick couldn't parse. The PostUp/PostDown hooks call the
 * helper's firewall commands, so their effect is modelled from the config's metadata.
 */
class FakeHost
{
    /** @var array<string, string> link => .conf content */
    public array $confs = [];

    /** @var array<string, string> "link/key" => client config content */
    public array $clients = [];

    /** @var array<string, string> link => utunN (macOS wg-quick name files) */
    public array $names = [];

    /** @var array<string, array{link: ?string, private_key: string, port: int, address: string, peers: array<string, array{psk: ?string, allowed_ips: string}>}> */
    public array $interfaces = [];

    /** @var array<string, array{forward: bool, nat: bool, nat6?: string}> live firewall state per link (nat6: the masqueraded IPv6 prefix) */
    public array $firewall = [];

    /** @var list<string> */
    public array $enabledUnits = [];

    /** Make the next link start fail, like a wg-quick error. */
    public bool $failNextStart = false;

    protected int $nextUtun = 4;

    public function __construct(
        public readonly string $os,
        public readonly FakeShell $shell,
    ) {
        $this->registerHelper();
        $os === 'mac' ? $this->registerMac() : $this->registerLinux();
        $this->shell
            ->on('curl -4 -s --max-time 5 :url', fn () => '203.0.113.10')
            ->on('curl -6 -s --max-time 5 :url', fn () => $this->fail());
    }

    // ─── Inspection helpers ──────────────────────────────────────────

    public function conf(string $link): ?string
    {
        return $this->confs[$link] ?? null;
    }

    /** Everything stored on the host: configs, client configs and macOS name files. */
    public function files(): array
    {
        return [...$this->confs, ...$this->clients, ...$this->names];
    }

    /** The OS interface a link runs as, or null when it is down. */
    public function interfaceOf(string $link): ?string
    {
        foreach ($this->interfaces as $iface => $interface) {
            if ($interface['link'] === $link) {
                return $iface;
            }
        }

        return null;
    }

    /** @return array<string, string> pubkey => allowed IPs, from the running interface */
    public function runtimePeers(string $link): array
    {
        $iface = $this->interfaceOf($link) ?? throw new LogicException("{$link} is not running");

        return array_map(fn (array $peer) => $peer['allowed_ips'], $this->interfaces[$iface]['peers']);
    }

    /** @return array<string, string> pubkey => allowed IPs, from the .conf */
    public function confPeers(string $link): array
    {
        $peers = [];
        foreach ($this->parse($this->conf($link) ?? '')['peers'] as $peer) {
            $peers[$peer['PublicKey']] = $peer['AllowedIPs'];
        }

        return $peers;
    }

    /** Live stats `wg show dump` reports for a peer of a running link. */
    public function setPeerStats(string $link, string $pubkey, string $endpoint, int $handshake, int $rx, int $tx): void
    {
        $iface = $this->interfaceOf($link) ?? throw new LogicException("{$link} is not running");
        $this->interfaces[$iface]['peers'][$pubkey]['stats'] = compact('endpoint', 'handshake', 'rx', 'tx');
    }

    /** Add a running WireGuard interface that no .conf manages. */
    public function addUnmanagedInterface(string $iface): void
    {
        $this->interfaces[$iface] = [
            'link' => null,
            'private_key' => base64_encode(random_bytes(32)),
            'port' => 40000,
            'address' => '192.168.99.1/24',
            'peers' => [],
        ];
    }

    // ─── The root helper ─────────────────────────────────────────────

    protected function registerHelper(): void
    {
        $helper = fn (string $command, callable $handler) => $this->shell->on("sudo -n :helper {$command}", $handler);

        $helper('version', fn () => '1');

        // Runtime state
        $helper('interfaces', fn () => implode(' ', array_keys($this->interfaces)));
        $helper('dump :iface', fn (array $b) => $this->dump($b['iface']));
        $helper('peer-add :iface', function (array $b, ?string $input) {
            $this->requireInterface($b['iface']);
            foreach ($this->parse((string) $input)['peers'] as $peer) {
                $this->interfaces[$b['iface']]['peers'][$peer['PublicKey']] = [
                    'psk' => $peer['PresharedKey'] ?? null,
                    'allowed_ips' => $peer['AllowedIPs'],
                ];
            }

            return '';
        });
        $helper('peer-remove :iface :pubkey', function (array $b) {
            $this->requireInterface($b['iface']);
            unset($this->interfaces[$b['iface']]['peers'][$b['pubkey']]);

            return '';
        });
        $helper('peer-ips :iface :pubkey :ips', function (array $b) {
            $this->requireInterface($b['iface']);
            // The helper hands wg the list without spaces
            $this->interfaces[$b['iface']]['peers'][$b['pubkey']]['allowed_ips'] = str_replace(' ', '', $b['ips']);

            return '';
        });

        // Link configs
        $helper('conf-list', fn () => implode("\n", array_keys($this->confs)));
        $helper('conf-read :name', fn (array $b) => $this->confs[$b['name']] ?? $this->fail("no config for link {$b['name']}"));
        $helper('conf-write :name', function (array $b, ?string $input) {
            $this->confs[$b['name']] = (string) $input;

            return '';
        });
        $helper('conf-delete :name', function (array $b) {
            unset($this->confs[$b['name']]);

            return '';
        });

        // Client configs
        $helper('client-read :link :key', fn (array $b) => $this->clients["{$b['link']}/{$b['key']}"] ?? $this->fail('no client config'));
        $helper('client-write :link :key', function (array $b, ?string $input) {
            $this->clients["{$b['link']}/{$b['key']}"] = (string) $input;

            return '';
        });
        $helper('client-delete :link :key', function (array $b) {
            unset($this->clients["{$b['link']}/{$b['key']}"]);

            return '';
        });
        $helper('client-delete-all :link', function (array $b) {
            foreach (array_keys($this->clients) as $key) {
                if (str_starts_with($key, "{$b['link']}/")) {
                    unset($this->clients[$key]);
                }
            }

            return '';
        });

        // Lifecycle: `down` is idempotent, like the real helper
        $helper('up :name', function (array $b) {
            $this->conf($b['name']) ?? $this->fail("no config for link {$b['name']}");
            $this->os === 'mac' ? $this->wgQuickUp($b['name']) : $this->systemdUp($b['name']);

            return '';
        });
        $helper('down :name', function (array $b) {
            $this->os === 'mac' ? $this->wgQuickDown($b['name']) : $this->systemdDown($b['name']);

            return '';
        });
        $helper('resolve :name', fn (array $b) => $this->os === 'mac' ? ($this->names[$b['name']] ?? $b['name']) : $b['name']);

        // Firewall: rules come from the saved config, as in the real helper
        $helper('firewall-up :link :iface', function (array $b) {
            $this->applyFirewall($b['link']);

            return '';
        });
        $helper('firewall-down :link', function (array $b) {
            unset($this->firewall[$b['link']]);

            return '';
        });
    }

    protected function dump(string $iface): string
    {
        $interface = $this->requireInterface($iface);
        $public_key = base64_encode(sodium_crypto_scalarmult_base(base64_decode($interface['private_key'])));

        $lines = ["{$interface['private_key']}\t{$public_key}\t{$interface['port']}\toff"];
        foreach ($interface['peers'] as $pubkey => $peer) {
            $stats = $peer['stats'] ?? ['endpoint' => '(none)', 'handshake' => 0, 'rx' => 0, 'tx' => 0];
            // As wg prints them: comma-separated, no spaces
            $allowed_ips = str_replace(' ', '', $peer['allowed_ips']);
            $lines[] = implode("\t", [$pubkey, $peer['psk'] ?? '(none)', $stats['endpoint'], $allowed_ips, $stats['handshake'], $stats['rx'], $stats['tx'], 'off']);
        }

        return implode("\n", $lines);
    }

    protected function requireInterface(string $iface): array
    {
        return $this->interfaces[$iface] ?? $this->fail("Unable to access interface: {$iface}");
    }

    protected function applyFirewall(string $link): void
    {
        $meta = $this->parse($this->conf($link) ?? $this->fail("no config for link {$link}"))['meta'];
        $state = ['forward' => ($meta['forward'] ?? 'false') === 'true', 'nat' => ($meta['nat'] ?? 'false') === 'true'];
        if ($state['nat'] && isset($meta['address6'])) {
            $state['nat6'] = $meta['address6'];
        }

        if ($state['forward'] || $state['nat']) {
            $this->firewall[$link] = $state;
        } else {
            unset($this->firewall[$link]);
        }
    }

    // ─── wg-quick ────────────────────────────────────────────────────

    protected function systemdUp(string $link): void
    {
        $this->enabledUnits = array_values(array_unique([...$this->enabledUnits, $link]));
        if (! isset($this->interfaces[$link])) {
            $this->bringUp($link, $link);
        }
    }

    protected function systemdDown(string $link): void
    {
        if (isset($this->interfaces[$link])) {
            $this->bringDown($link, $link);
        }
        $this->enabledUnits = array_values(array_diff($this->enabledUnits, [$link]));
    }

    protected function wgQuickUp(string $link): void
    {
        if (isset($this->names[$link])) {
            $this->fail("wg-quick: `{$link}' already exists");
        }

        $iface = 'utun'.$this->nextUtun++;
        $this->bringUp($link, $iface);
        $this->names[$link] = $iface;
    }

    protected function wgQuickDown(string $link): void
    {
        if (isset($this->names[$link])) {
            $this->bringDown($link, $this->names[$link]);
            unset($this->names[$link]);
        }
    }

    protected function bringUp(string $link, string $iface): void
    {
        $conf = $this->conf($link) ?? $this->fail("wg-quick: `{$link}' does not exist");

        if ($this->failNextStart) {
            $this->failNextStart = false;
            $this->fail("wg-quick: failed to start {$link}");
        }

        $this->assertWgQuickCanParse($conf);
        $parsed = $this->parse($conf);

        $peers = [];
        foreach ($parsed['peers'] as $peer) {
            $peers[$peer['PublicKey']] = ['psk' => $peer['PresharedKey'] ?? null, 'allowed_ips' => $peer['AllowedIPs']];
        }

        $this->interfaces[$iface] = [
            'link' => $link,
            'private_key' => $parsed['interface']['PrivateKey'],
            'port' => (int) $parsed['interface']['ListenPort'],
            'address' => $parsed['interface']['Address'],
            'peers' => $peers,
        ];

        // PostUp = <helper> firewall-up …
        if (isset($parsed['interface']['PostUp'])) {
            $this->applyFirewall($link);
        }
    }

    protected function bringDown(string $link, string $iface): void
    {
        unset($this->interfaces[$iface]);

        // PostDown = <helper> firewall-down …
        if (isset($this->parse($this->conf($link) ?? '')['interface']['PostDown'])) {
            unset($this->firewall[$link]);
        }
    }

    /**
     * wg-quick reads the config line by line: anything that isn't blank, a comment, a section
     * header or `Key = value` ends up in `wg setconf` and fails.
     */
    protected function assertWgQuickCanParse(string $conf): void
    {
        foreach (explode("\n", $conf) as $line) {
            $line = trim($line);
            if ($line === '' || str_starts_with($line, '#') || in_array($line, ['[Interface]', '[Peer]'], true)) {
                continue;
            }
            if (! preg_match('/^[A-Za-z]+\s*=\s*\S/', $line)) {
                throw new LogicException("wg-quick would reject config line: {$line}");
            }
        }
    }

    // ─── Unprivileged system tools ───────────────────────────────────

    protected function registerLinux(): void
    {
        $this->shell
            ->on('ip address show dev :ifname', function (array $b) {
                $interface = $this->requireInterface($b['ifname']);
                $lines = ["7: {$b['ifname']}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420", '    link/none'];
                foreach (array_map('trim', explode(',', $interface['address'])) as $address) {
                    $family = str_contains($address, ':') ? 'inet6' : 'inet';
                    $lines[] = "    {$family} {$address} scope global {$b['ifname']}";
                }

                return implode("\n", $lines);
            })
            ->on('ip link show', function () {
                $lines = ['1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536', '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500'];
                $n = 3;
                foreach (array_keys($this->interfaces) as $iface) {
                    $lines[] = ($n++).": {$iface}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420";
                }

                return implode("\n", $lines);
            })
            ->on('ip route show default', fn () => 'default via 192.0.2.1 dev eth0 proto static');
    }

    protected function registerMac(): void
    {
        $this->shell
            ->on('ifconfig :ifname', function (array $b) {
                $addresses = array_map('trim', explode(',', $this->requireInterface($b['ifname'])['address']));
                [$ip, $mask] = explode('/', $addresses[0]);
                $hex = sprintf('0x%08x', (0xFFFFFFFF << (32 - (int) $mask)) & 0xFFFFFFFF);
                $output = "{$b['ifname']}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n"
                    ."\tinet {$ip} --> {$ip} netmask {$hex}";
                if (isset($addresses[1])) {
                    [$ip6, $prefix] = explode('/', $addresses[1]);
                    $output .= "\n\tinet6 {$ip6} prefixlen {$prefix}";
                }

                return $output;
            })
            ->on('ifconfig -l', fn () => implode(' ', ['lo0', 'en0', ...array_keys($this->interfaces)]))
            ->on('route -n get default 2>/dev/null', fn () => "   route to: default\ndestination: default\n  interface: en0");
    }

    // ─── Shared ──────────────────────────────────────────────────────

    /**
     * Minimal wg-quick style parser, kept independent from the app's ConfigBuilder.
     *
     * @return array{meta: array<string, string>, interface: array<string, string>, peers: list<array<string, string>>}
     */
    protected function parse(string $content): array
    {
        $result = ['meta' => [], 'interface' => [], 'peers' => []];
        $section = null;

        foreach (explode("\n", $content) as $line) {
            $line = trim($line);
            if ($line === '[Interface]') {
                $section = 'interface';
            } elseif ($line === '[Peer]') {
                $section = 'peer';
                $result['peers'][] = [];
            } elseif ($section === null && preg_match('/^#\s*(\w+)\s*=\s*(.+)$/', $line, $m)) {
                $result['meta'][$m[1]] = $m[2];
            } elseif ($section !== null && preg_match('/^(\w+)\s*=\s*(.+)$/', $line, $m)) {
                if ($section === 'interface') {
                    $result['interface'][$m[1]] = $m[2];
                } else {
                    $result['peers'][count($result['peers']) - 1][$m[1]] = $m[2];
                }
            }
        }

        return $result;
    }

    protected function fail(string $message = 'command failed'): never
    {
        throw new CommandFailed($message);
    }
}
