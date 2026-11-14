<?php

namespace Tests\Fakes;

use LogicException;

/**
 * An in-memory host behind FakeShell, modelled on how the real tools behave:
 *
 * - Linux: `systemctl start wg-quick@<link>` creates an interface named after the link; one
 *   nftables table `inet wg_<link>` per link.
 * - macOS: `wg-quick up <link>` creates the next free utunN and records it in
 *   /var/run/wireguard/<link>.name (removed again by `wg-quick down`); one pf anchor `wg/<link>`.
 *
 * Starting a link rejects config lines wg-quick couldn't parse. PostUp/PostDown hooks are not
 * executed here (the driver tests run them in bash); their effect is modelled from the metadata.
 */
class FakeHost
{
    /** @var array<string, string> path => content */
    public array $files = [];

    /** @var array<string, array{link: ?string, private_key: string, port: int, address: string, peers: array<string, array{psk: ?string, allowed_ips: string}>}> */
    public array $interfaces = [];

    /** @var array<string, array{forward: bool, nat: bool}> live firewall state per link */
    public array $firewall = [];

    /** @var array<string, string> pf anchor => loaded ruleset (macOS) */
    public array $anchors = [];

    /** @var list<string> */
    public array $enabledUnits = [];

    /** @var list<string> permission bits of each staging file when it was copied into place */
    public array $stagedModes = [];

    /** Make the next link start fail, like a wg-quick error. */
    public bool $failNextStart = false;

    protected int $nextUtun = 4;

    public function __construct(
        public readonly string $os,
        public readonly FakeShell $shell,
        public readonly string $configPath,
        public readonly string $stagingDir,
    ) {
        $this->registerFiles();
        $this->registerWireGuard();
        $os === 'mac' ? $this->registerMac() : $this->registerLinux();
    }

    // ─── Inspection helpers ──────────────────────────────────────────

    public function conf(string $link): ?string
    {
        return $this->files["{$this->configPath}/{$link}.conf"] ?? null;
    }

    public function clientConfig(string $link, string $safe_pubkey): ?string
    {
        return $this->files["{$this->configPath}/clients/{$link}/{$safe_pubkey}.conf"] ?? null;
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

    // ─── Files (config dir, client configs, /var/run/wireguard) ──────

    protected function registerFiles(): void
    {
        $this->shell
            ->on('sudo cat :path', fn (array $b) => $this->files[$b['path']] ?? $this->fail())
            ->on('sudo test -f :path && echo 1', fn (array $b) => isset($this->files[$b['path']]) ? '1' : $this->fail())
            ->on('sudo ls :path', fn (array $b) => implode("\n", $this->ls($b['path'])))
            ->on('sudo mkdir -p :dir && sudo cp :tmp :path && sudo chmod 600 :path', function (array $b) {
                if (! str_starts_with($b['tmp'], $this->stagingDir.'/')) {
                    throw new LogicException("Staging file {$b['tmp']} is outside {$this->stagingDir}; sudoers would reject the cp");
                }
                if (dirname($b['path']) !== $b['dir']) {
                    throw new LogicException("mkdir {$b['dir']} does not create the parent of {$b['path']}");
                }

                clearstatcache();
                $this->stagedModes[] = sprintf('%04o', fileperms($b['tmp']) & 0777);
                $this->files[$b['path']] = file_get_contents($b['tmp']);

                return '';
            })
            ->on('sudo rm -f :path', function (array $b) {
                unset($this->files[$b['path']]);

                return '';
            })
            ->on('sudo rm -rf :dir', function (array $b) {
                foreach (array_keys($this->files) as $path) {
                    if (str_starts_with($path, $b['dir'].'/')) {
                        unset($this->files[$path]);
                    }
                }

                return '';
            })
            ->on('curl -4 -s --max-time 5 :url', fn () => '203.0.113.10')
            ->on('curl -6 -s --max-time 5 :url', fn () => $this->fail());
    }

    /** @return list<string> entries directly inside $dir */
    protected function ls(string $dir): array
    {
        $entries = [];
        foreach (array_keys($this->files) as $path) {
            if (str_starts_with($path, $dir.'/')) {
                $entries[] = explode('/', substr($path, strlen($dir) + 1))[0];
            }
        }

        $entries = array_values(array_unique($entries));
        sort($entries);

        return $entries;
    }

    // ─── wg ──────────────────────────────────────────────────────────

    protected function registerWireGuard(): void
    {
        $this->shell
            ->on('sudo wg show interfaces', fn () => implode(' ', array_keys($this->interfaces)))
            ->on('sudo wg show :iface dump', fn (array $b) => $this->dump($b['iface']))
            ->on('sudo wg addconf :iface /dev/stdin', function (array $b, ?string $input) {
                $this->requireInterface($b['iface']);
                foreach ($this->parse((string) $input)['peers'] as $peer) {
                    $this->interfaces[$b['iface']]['peers'][$peer['PublicKey']] = [
                        'psk' => $peer['PresharedKey'] ?? null,
                        'allowed_ips' => $peer['AllowedIPs'],
                    ];
                }

                return '';
            })
            ->on('sudo wg set :iface peer :pubkey remove', function (array $b) {
                $this->requireInterface($b['iface']);
                unset($this->interfaces[$b['iface']]['peers'][$b['pubkey']]);

                return '';
            })
            ->on('sudo wg set :iface peer :pubkey allowed-ips :ips', function (array $b) {
                $this->requireInterface($b['iface']);
                $this->interfaces[$b['iface']]['peers'][$b['pubkey']] ??= ['psk' => null, 'allowed_ips' => ''];
                $this->interfaces[$b['iface']]['peers'][$b['pubkey']]['allowed_ips'] = $b['ips'];

                return '';
            });
    }

    protected function dump(string $iface): string
    {
        $interface = $this->requireInterface($iface);
        $public_key = base64_encode(sodium_crypto_scalarmult_base(base64_decode($interface['private_key'])));

        $lines = ["{$interface['private_key']}\t{$public_key}\t{$interface['port']}\toff"];
        foreach ($interface['peers'] as $pubkey => $peer) {
            $lines[] = implode("\t", [$pubkey, $peer['psk'] ?? '(none)', '(none)', $peer['allowed_ips'], '0', '0', '0', 'off']);
        }

        return implode("\n", $lines);
    }

    protected function requireInterface(string $iface): array
    {
        return $this->interfaces[$iface] ?? $this->fail("Unable to access interface: {$iface}");
    }

    // ─── wg-quick lifecycle ──────────────────────────────────────────

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

        if (isset($parsed['interface']['PostUp'])) {
            $this->firewall[$link] = [
                'forward' => ($parsed['meta']['forward'] ?? 'false') === 'true',
                'nat' => ($parsed['meta']['nat'] ?? 'false') === 'true',
            ];
        }
    }

    protected function bringDown(string $link, string $iface): void
    {
        unset($this->interfaces[$iface]);

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

    // ─── Linux: systemd + iproute2 + nftables ────────────────────────

    protected function registerLinux(): void
    {
        $this->shell
            ->on('sudo systemctl enable :unit && sudo systemctl start :unit', function (array $b) {
                $link = $this->unitLink($b['unit']);
                $this->enabledUnits = array_values(array_unique([...$this->enabledUnits, $link]));
                if (! isset($this->interfaces[$link])) {
                    $this->bringUp($link, $link);
                }

                return '';
            })
            ->on('sudo systemctl stop :unit && sudo systemctl disable :unit', function (array $b) {
                $link = $this->unitLink($b['unit']);
                if (isset($this->interfaces[$link])) {
                    $this->bringDown($link, $link);
                }
                $this->enabledUnits = array_values(array_diff($this->enabledUnits, [$link]));

                return '';
            })
            ->on('ip address show dev :ifname', function (array $b) {
                $interface = $this->requireInterface($b['ifname']);

                return "7: {$b['ifname']}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420\n"
                    ."    link/none\n    inet {$interface['address']} scope global {$b['ifname']}";
            })
            ->on('ip link show', function () {
                $lines = ['1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536', '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500'];
                $n = 3;
                foreach (array_keys($this->interfaces) as $iface) {
                    $lines[] = ($n++).": {$iface}: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420";
                }

                return implode("\n", $lines);
            })
            ->on('ip route show default', fn () => 'default via 192.0.2.1 dev eth0 proto static')
            ->on('sudo nft add table inet :table', function (array $b) {
                $this->firewall[$this->tableLink($b['table'])] ??= ['forward' => false, 'nat' => false];

                return '';
            })
            ->on("sudo nft add chain inet :table forward '{ type filter hook forward priority 0; }'", fn (array $b) => $this->nftChain($b['table'], 'forward'))
            ->on("sudo nft add chain inet :table postrouting '{ type nat hook postrouting priority 100; }'", fn (array $b) => $this->nftChain($b['table'], 'nat'))
            ->on('sudo nft add rule inet :table forward iifname :iface accept', fn (array $b) => $this->nftRule($b['table'], 'forward'))
            ->on('sudo nft add rule inet :table forward oifname :iface accept', fn (array $b) => $this->nftRule($b['table'], 'forward'))
            ->on('sudo nft add rule inet :table postrouting oifname :ifout masquerade', fn (array $b) => $this->nftRule($b['table'], 'nat'))
            ->on('sudo nft delete table inet :table', function (array $b) {
                $link = $this->tableLink($b['table']);
                if (! isset($this->firewall[$link])) {
                    $this->fail("No such file or directory: table {$b['table']}");
                }
                unset($this->firewall[$link]);

                return '';
            });
    }

    protected function nftChain(string $table, string $kind): string
    {
        $link = $this->tableLink($table);
        if (! isset($this->firewall[$link])) {
            $this->fail("No such file or directory: table {$table}");
        }
        $this->firewall[$link][$kind] = true;

        return '';
    }

    protected function nftRule(string $table, string $kind): string
    {
        if (! ($this->firewall[$this->tableLink($table)][$kind] ?? false)) {
            $this->fail("No such file or directory: chain for {$kind} in {$table}");
        }

        return '';
    }

    protected function unitLink(string $unit): string
    {
        return str_starts_with($unit, 'wg-quick@') ? substr($unit, 9) : throw new LogicException("Unexpected unit {$unit}");
    }

    protected function tableLink(string $table): string
    {
        return str_starts_with($table, 'wg_') ? substr($table, 3) : throw new LogicException("Unexpected nft table {$table}");
    }

    // ─── macOS: wg-quick + utunN + pf ────────────────────────────────

    protected function registerMac(): void
    {
        $this->shell
            ->on('sudo wg-quick up :name', function (array $b) {
                $name_file = "/var/run/wireguard/{$b['name']}.name";
                if (isset($this->files[$name_file])) {
                    $this->fail("wg-quick: `{$b['name']}' already exists");
                }

                $iface = 'utun'.$this->nextUtun++;
                $this->bringUp($b['name'], $iface);
                $this->files[$name_file] = "{$iface}\n";

                return '';
            })
            ->on('sudo wg-quick down :name', function (array $b) {
                $name_file = "/var/run/wireguard/{$b['name']}.name";
                $iface = trim($this->files[$name_file] ?? $this->fail("wg-quick: `{$b['name']}' is not a WireGuard interface"));

                $this->bringDown($b['name'], $iface);
                unset($this->files[$name_file]);

                return '';
            })
            ->on('ifconfig :ifname', function (array $b) {
                [$ip, $mask] = explode('/', $this->requireInterface($b['ifname'])['address']);
                $hex = sprintf('0x%08x', (0xFFFFFFFF << (32 - (int) $mask)) & 0xFFFFFFFF);

                return "{$b['ifname']}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n"
                    ."\tinet {$ip} --> {$ip} netmask {$hex}";
            })
            ->on('ifconfig -l', fn () => implode(' ', ['lo0', 'en0', ...array_keys($this->interfaces)]))
            ->on('route -n get default 2>/dev/null', fn () => "   route to: default\ndestination: default\n  interface: en0")
            ->on('sudo pfctl -a :anchor -f -', function (array $b, ?string $input) {
                $this->anchors[$b['anchor']] = (string) $input;
                $this->firewall[$this->anchorLink($b['anchor'])] = [
                    'forward' => str_contains((string) $input, 'pass '),
                    'nat' => str_contains((string) $input, 'nat on '),
                ];

                return '';
            })
            ->on('sudo pfctl -a :anchor -F all', function (array $b) {
                unset($this->anchors[$b['anchor']], $this->firewall[$this->anchorLink($b['anchor'])]);

                return '';
            })
            ->on('sudo pfctl -e', fn () => '');
    }

    protected function anchorLink(string $anchor): string
    {
        return str_starts_with($anchor, 'wg/') ? substr($anchor, 3) : throw new LogicException("Unexpected pf anchor {$anchor}");
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
