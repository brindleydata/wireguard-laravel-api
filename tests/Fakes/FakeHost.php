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
 *
 * A config the app didn't write (hooks of its own, SaveConfig) behaves as wg-quick makes it: its
 * hooks run when its link starts and stops (see $hooks), and with SaveConfig the interface is
 * written into it when the link stops.
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

    /** @var array<string, array{forward: bool, nat: bool, nat6?: string, inbound?: true, destinations?: string}> live firewall state per link (nat6: the masqueraded IPv6 prefix; inbound: connections into the tunnel, not only replies; destinations: where traffic out of it may go) */
    public array $firewall = [];

    /** @var array<string, string> link => what a hook of its own (not the helper's) set up when the link started, until its PostDown ran */
    public array $hooks = [];

    /** @var array<string, string> link => the config an adoption replaced, while the helper keeps it */
    public array $kept = [];

    /** @var array{allow_default_route: bool, allow_own_networks: bool} the server's route policy (the helper's `policy`) */
    public array $policy = ['allow_default_route' => false, 'allow_own_networks' => false];

    /** @var list<string> names that don't resolve (every other one does) */
    public array $unresolvable = [];

    /** This machine's name (`hostname`): an FQDN, so a new link's endpoint is detected as it */
    public string $hostname = 'vpn.example.test';

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

    /** Everything stored on the host: configs, client configs, macOS name files, and a config an adoption left behind. */
    public function files(): array
    {
        $kept = [];
        foreach ($this->kept as $link => $conf) {
            $kept[".{$link}.conf.before-adopt"] = $conf;
        }

        return [...$this->confs, ...$this->clients, ...$this->names, ...$kept];
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

    /**
     * Add a running WireGuard interface that no .conf manages (started by something else).
     *
     * @param  array<string, string>  $peers  pubkey => allowed IPs
     */
    public function addUnmanagedInterface(string $iface, array $peers = []): void
    {
        $this->interfaces[$iface] = [
            'link' => null,
            'private_key' => base64_encode(random_bytes(32)),
            'port' => 40000,
            'address' => '192.168.99.1/24',
            'peers' => array_map(fn (string $allowed_ips) => ['psk' => null, 'allowed_ips' => $allowed_ips], $peers),
        ];
    }

    // ─── The root helper ─────────────────────────────────────────────

    protected function registerHelper(): void
    {
        $helper = fn (string $command, callable $handler) => $this->shell->on("sudo -n :helper {$command}", $handler);

        $this->shell->on('hostname', fn () => $this->hostname);
        $helper('version', fn () => '1');
        $helper('policy', fn () => implode("\n", array_map(fn (string $key, bool $on) => "{$key}=".($on ? 'true' : 'false'), array_keys($this->policy), $this->policy)));

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
        $helper('link-key :iface', function (array $b, ?string $input) {
            $this->requireInterface($b['iface']);
            $this->interfaces[$b['iface']]['private_key'] = trim((string) $input);

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
        $helper('conf-read :name', fn (array $b) => $this->confs[$b['name']] ?? $this->missing("no config for link {$b['name']}"));
        $helper('conf-write :name', function (array $b, ?string $input) {
            $this->confs[$b['name']] = (string) $input;

            return '';
        });
        $helper('conf-delete :name', function (array $b) {
            unset($this->confs[$b['name']], $this->kept[$b['name']]);

            return '';
        });
        // Adoption: the helper checks a config without writing it, and keeps the one a new one
        // replaces until it is told the outcome
        $helper('conf-check :name', fn () => '');
        $helper('conf-adopt :name', function (array $b, ?string $input) {
            $this->kept[$b['name']] = $this->confs[$b['name']] ?? $this->missing("no config for link {$b['name']}");
            $this->confs[$b['name']] = (string) $input;

            return '';
        });
        $helper('conf-adopt-undo :name', function (array $b) {
            $this->confs[$b['name']] = $this->kept[$b['name']] ?? $this->fail("no config of link {$b['name']} from before an adoption is kept");
            unset($this->kept[$b['name']]);

            return '';
        });
        $helper('conf-adopt-done :name', function (array $b) {
            unset($this->kept[$b['name']]);

            return '';
        });

        // Client configs
        $helper('client-read :link :key', fn (array $b) => $this->clients["{$b['link']}/{$b['key']}"] ?? $this->missing('no client config'));
        $helper('client-write :link :key', function (array $b, ?string $input) {
            $this->clients["{$b['link']}/{$b['key']}"] = (string) $input;

            return '';
        });
        $helper('client-delete :link :key', function (array $b) {
            unset($this->clients["{$b['link']}/{$b['key']}"]);

            return '';
        });
        // Whose keys a link's client directory has: the app's files are named by public key, an
        // older API's by anything else (the peer's address)
        $helper('client-keys :link', function (array $b) {
            $lines = [];
            foreach ($this->clientKeys($b['link']) as $file => [$kind, $pubkey]) {
                $lines[] = "{$kind} {$pubkey}";
            }

            return implode("\n", $lines);
        });
        $helper('client-import :link', function (array $b) {
            $conf = $this->confs[$b['link']] ?? $this->missing("no config for link {$b['link']}");
            preg_match_all('/^(?:# )?PublicKey = (\S+)$/m', $conf, $peers);
            $stored = array_column(array_filter($this->clientKeys($b['link']), fn (array $key) => $key[0] === 'stored'), 1);

            $imported = [];
            foreach ($this->clientKeys($b['link']) as $file => [$kind, $pubkey]) {
                if ($kind === 'legacy' && in_array($pubkey, $peers[1], true) && ! in_array($pubkey, [...$stored, ...$imported], true)) {
                    preg_match('/^\s*PrivateKey\s*=\s*(\S+)/m', $this->clients[$file], $key);
                    $this->clients["{$b['link']}/".rtrim(strtr($pubkey, '+/', '-_'), '=')] = "# This peer's private key, taken over.\nPrivateKey = {$key[1]}\n";
                    $imported[] = $pubkey;
                }
            }

            return implode("\n", $imported);
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
        $helper('firewall-check :link :iface', fn (array $b) => $this->firewallExpected($b['link']) === ($this->firewall[$b['link']] ?? null) ? 'ok' : 'missing');
        $helper('firewall-down :link', function (array $b) {
            unset($this->firewall[$b['link']]);

            return '';
        });
    }

    /** @return array<string, array{0: string, 1: string}> "link/file" => ['stored'|'legacy', public key] */
    protected function clientKeys(string $link): array
    {
        $keys = [];
        foreach ($this->clients as $file => $content) {
            if (! str_starts_with($file, "{$link}/")) {
                continue;
            }
            $name = substr($file, strlen($link) + 1);
            if (preg_match('/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/', $name)) {
                $keys[$file] = ['stored', strtr($name, '-_', '+/').'='];
            } elseif (preg_match('/^\s*PrivateKey\s*=\s*([A-Za-z0-9+\/]{42}[AEIMQUYcgkosw048]=)\s*$/m', $content, $key)) {
                $keys[$file] = ['legacy', base64_encode(sodium_crypto_scalarmult_base(base64_decode($key[1])))];
            }
        }

        return $keys;
    }

    protected function dump(string $iface): string
    {
        $interface = $this->requireInterface($iface);
        $public_key = base64_encode(sodium_crypto_scalarmult_base(base64_decode($interface['private_key'])));

        $lines = ["{$interface['private_key']}\t{$public_key}\t{$interface['port']}\t".($interface['fwmark'] ?? 'off')];
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
        $state = $this->firewallExpected($link);

        if ($state !== null) {
            $this->firewall[$link] = $state;
        } else {
            unset($this->firewall[$link]);
        }
    }

    /** The rules a link's config asks for (null: none). */
    protected function firewallExpected(string $link): ?array
    {
        $meta = $this->parse($this->conf($link) ?? $this->fail("no config for link {$link}"))['meta'];
        $state = ['forward' => ($meta['forward'] ?? 'false') === 'true', 'nat' => ($meta['nat'] ?? 'false') === 'true'];
        if ($state['nat'] && isset($meta['address6'])) {
            $state['nat6'] = $meta['address6'];
        }
        // Forwarding into the tunnel takes connections that start outside, not only replies
        if ($state['forward'] && ($meta['inbound'] ?? 'false') === 'true') {
            $state['inbound'] = true;
        }
        // Out of the tunnel (and NAT) only to these, whatever forward says
        if (isset($meta['destinations'])) {
            $state['destinations'] = $meta['destinations'];
        }

        return $state['forward'] || $state['nat'] || isset($state['destinations']) ? $state : null;
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

        // PostUp = <helper> firewall-up …, or a hook of the config's own
        if (str_contains($parsed['interface']['PostUp'] ?? '', ' firewall-up ')) {
            $this->applyFirewall($link);
        } elseif (isset($parsed['interface']['PostUp'])) {
            $this->hooks[$link] = $parsed['interface']['PostUp'];
        }
    }

    protected function bringDown(string $link, string $iface): void
    {
        $interface = $this->interfaces[$iface];
        unset($this->interfaces[$iface]);
        $parsed = $this->parse($this->conf($link) ?? '');

        // PostDown = <helper> firewall-down …, or a hook of the config's own: the one of the
        // config as it is now, which only undoes what its own PostUp did
        if (str_contains($parsed['interface']['PostDown'] ?? '', ' firewall-down ')) {
            unset($this->firewall[$link]);
        } elseif (isset($parsed['interface']['PostDown'])) {
            unset($this->hooks[$link]);
        }
        // SaveConfig = true: wg-quick writes the config from the interface (`wg showconf`)
        if (($parsed['interface']['SaveConfig'] ?? '') === 'true') {
            $this->confs[$link] = $this->savedConfig($parsed['interface'], $interface);
        }
    }

    /** A config as wg-quick saves it: its own lines first, then what `wg showconf` prints. */
    protected function savedConfig(array $own, array $interface): string
    {
        $lines = ['[Interface]', "Address = {$own['Address']}", 'SaveConfig = true'];
        foreach (['PostUp', 'PostDown'] as $hook) {
            if (isset($own[$hook])) {
                $lines[] = "{$hook} = {$own[$hook]}";
            }
        }
        array_push($lines, "ListenPort = {$interface['port']}", "PrivateKey = {$interface['private_key']}");
        foreach ($interface['peers'] as $pubkey => $peer) {
            array_push($lines, '', '[Peer]', "PublicKey = {$pubkey}");
            if ($peer['psk'] !== null) {
                $lines[] = "PresharedKey = {$peer['psk']}";
            }
            $lines[] = 'AllowedIPs = '.implode(', ', array_map('trim', explode(',', $peer['allowed_ips'])));
            if (isset($peer['stats']['endpoint'])) {
                $lines[] = "Endpoint = {$peer['stats']['endpoint']}";
            }
        }

        return implode("\n", $lines)."\n";
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
            ->on('ip route show default', fn () => 'default via 192.0.2.1 dev eth0 proto static')
            // As getent answers: a line per address, exit status 2 for a name that doesn't resolve
            ->on('getent ahosts :host', fn (array $b) => in_array($b['host'], $this->unresolvable, true)
                ? throw new CommandFailed('Command failed with exit code 2', exitCode: 2)
                : "192.0.2.77      STREAM {$b['host']}\n192.0.2.77      DGRAM\n192.0.2.77      RAW")
            ->on('ip -o address show', function () {
                $lines = ['1: lo    inet 127.0.0.1/8 scope host lo', '2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0', '2: eth0    inet6 2001:db8:f::10/64 scope global'];
                foreach ($this->interfaces as $iface => $interface) {
                    foreach (array_map('trim', explode(',', $interface['address'])) as $address) {
                        $lines[] = "7: {$iface}    ".(str_contains($address, ':') ? 'inet6' : 'inet')." {$address} scope global {$iface}";
                    }
                }

                return implode("\n", $lines);
            });
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
            ->on('route -n get default 2>/dev/null', fn () => "   route to: default\ndestination: default\n    gateway: 192.0.2.1\n  interface: en0")
            // As dscacheutil answers: nothing (and exit status 0) for a name that doesn't resolve
            ->on('dscacheutil -q host -a name :host', fn (array $b) => in_array($b['host'], $this->unresolvable, true)
                ? ''
                : "name: {$b['host']}\nip_address: 192.0.2.77")
            ->on('ifconfig', function () {
                $output = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1\n"
                    ."en0: flags=8863<UP,BROADCAST,RUNNING> mtu 1500\n\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n\tinet6 2001:db8:f::10 prefixlen 64\n";
                foreach ($this->interfaces as $iface => $interface) {
                    $output .= "{$iface}: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n";
                    foreach (array_map('trim', explode(',', $interface['address'])) as $address) {
                        $output .= "\t".(str_contains($address, ':') ? 'inet6' : 'inet').' '.explode('/', $address)[0]."\n";
                    }
                }

                return $output;
            });
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
        throw new CommandFailed($message, exitCode: 1);
    }

    /** The helper's "no such config" (exit status 3), which the app reads as null. */
    protected function missing(string $message): never
    {
        throw new CommandFailed($message, exitCode: 3);
    }
}
