<?php

namespace App\Services;

/**
 * A wg-quick config as something other than this app wrote it (by hand, by the API before this
 * one), read for its adoption. ConfigBuilder::parseConfContent() reads what the app writes, and
 * silently passes over the rest; this accounts for every line:
 *
 * - what the app's own format holds too: the key, the port, the addresses, an MTU, the peers;
 * - what an adoption drops, because the app does that itself or it says nothing (`dropped`):
 *   hooks, comments, a setting that only spells out wg-quick's default;
 * - what can't be carried over, so the config can't be adopted as it is (`blocking`).
 *
 * Both are named by key only: a line may hold a secret. It reads a config as wg-quick and wg do:
 * keys and section names in any case, a `#` starting a comment anywhere in a line, and a key that
 * may come more than once (Address, AllowedIPs, the hooks). Whether the values are any good is
 * for whoever adopts it (WireGuard::adoptLink()).
 */
final class ForeignConfig
{
    /** Comments before [Interface] that are the app's own settings: kept (the config was the app's once) */
    private const METADATA = ['ifout', 'endpoint', 'forward', 'nat', 'inbound', 'destinations', 'allow_default_route', 'allow_own_networks', 'dns', 'keepalive', 'allowed_ips'];

    /** The app's own comments that an adoption writes anew, so they are neither kept nor counted as dropped */
    private const REWRITTEN = ['address', 'address6', 'format'];

    private const HOOKS = ['preup' => 'PreUp', 'postup' => 'PostUp', 'predown' => 'PreDown', 'postdown' => 'PostDown'];

    private const PEER_KEYS = ['publickey' => 'public_key', 'presharedkey' => 'preshared_key', 'endpoint' => 'endpoint', 'persistentkeepalive' => 'persistent_keepalive'];

    public ?string $privateKey = null;

    public ?string $listenPort = null;

    public ?string $mtu = null;

    /** @var list<string> every address of every Address line */
    public array $addresses = [];

    /** @var array<string, string> the app's own settings, where the config has them */
    public array $metadata = [];

    /**
     * @var list<array{public_key: ?string, preshared_key: ?string, allowed_ips: list<string>, endpoint: ?string, persistent_keepalive: ?string, enabled: bool, name: ?string, dns: ?string, keepalive: ?string, client_allowed_ips: ?string}>
     */
    public array $peers = [];

    /** @var array<string, int> what an adoption drops => how many lines of it */
    public array $dropped = [];

    /** @var list<string> what can't be carried over */
    public array $blocking = [];

    /** `SaveConfig = true`: wg-quick writes this config itself, from the interface, when the link stops */
    public bool $savesItself = false;

    public static function parse(string $content): self
    {
        $config = new self;
        $section = null;
        $interface = false;

        foreach (preg_split('/\r?\n/', $content) as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }

            // A peer the app disabled: its whole section is commented out
            if ($line === ConfigBuilder::DISABLED_PEER) {
                $section = 'disabled';
                $config->peers[] = self::peer(enabled: false);

                continue;
            }
            if ($line[0] === '#') {
                $config->comment($line, $section);

                continue;
            }
            // For wg-quick and wg, a # ends the line wherever it is
            if (($at = strpos($line, '#')) !== false) {
                $line = rtrim(substr($line, 0, $at));
                $config->drop('comments');
            }

            if (preg_match('/^\[(interface|peer)\]$/i', $line, $m)) {
                if (strtolower($m[1]) === 'peer') {
                    $section = 'peer';
                    $config->peers[] = self::peer(enabled: true);
                } else {
                    if ($interface) {
                        $config->block('a second [Interface]');
                    }
                    $section = 'interface';
                    $interface = true;
                }

                continue;
            }

            // In a disabled peer's section every line of it is a comment: one that isn't belongs to
            // whatever section wg sees there, which nothing here can say
            if (! preg_match('/^([A-Za-z0-9]+)\s*=\s*(.*)$/', $line, $m) || $section === null || $section === 'disabled') {
                $config->block('other lines');

                continue;
            }
            $section === 'interface'
                ? $config->interfaceLine($m[1], trim($m[2]))
                : $config->peerLine($m[1], trim($m[2]));
        }

        if (! $interface) {
            $config->block('no [Interface]');
        }

        return $config;
    }

    /** A peer with nothing known of it yet. */
    public static function peer(bool $enabled = true): array
    {
        return ['public_key' => null, 'preshared_key' => null, 'allowed_ips' => [], 'endpoint' => null, 'persistent_keepalive' => null, 'enabled' => $enabled,
            'name' => null, 'dns' => null, 'keepalive' => null, 'client_allowed_ips' => null];
    }

    private function comment(string $line, ?string $section): void
    {
        $setting = preg_match('/^#\s*(\w+)\s*=\s*(.+)$/', $line, $m) ? [$m[1], trim($m[2])] : null;

        if ($section === null && $setting !== null && in_array($setting[0], self::METADATA, true)) {
            $this->metadata[$setting[0]] = $setting[1];

            return;
        }
        if ($section === null && $setting !== null && in_array($setting[0], self::REWRITTEN, true)) {
            return;
        }
        if (in_array($section, ['peer', 'disabled'], true) && $setting !== null) {
            // A peer's label and its own client settings, as the app keeps them with it
            if (($field = array_search($setting[0], ConfigBuilder::PEER_SETTINGS, true)) !== false) {
                $this->peers[array_key_last($this->peers)][$field] = $setting[1];

                return;
            }
            if ($section === 'disabled' && (isset(self::PEER_KEYS[strtolower($setting[0])]) || strtolower($setting[0]) === 'allowedips')) {
                $this->peerLine($setting[0], $setting[1]);

                return;
            }
        }

        $this->drop('comments');
    }

    private function interfaceLine(string $key, string $value): void
    {
        $lower = strtolower($key);

        match (true) {
            $lower === 'address' => array_push($this->addresses, ...array_values(array_filter(array_map('trim', explode(',', $value)), fn (string $entry) => $entry !== ''))),
            $lower === 'privatekey' => $this->once($this->privateKey, 'PrivateKey', $value),
            $lower === 'listenport' => $this->once($this->listenPort, 'ListenPort', $value),
            $lower === 'mtu' => $this->once($this->mtu, 'MTU', $value),
            // The app installs a link's forward and NAT rules itself: hooks of its own are what it
            // replaces. (The app's own hook, in a config that was the app's once, is written anew.)
            isset(self::HOOKS[$lower]) => preg_match('#^\S*wgla-helper firewall-(up|down)( %[iI])+$#', $value) ? null : $this->drop(self::HOOKS[$lower]),
            // The app writes the config itself, at every change. (What wg-quick would save at the
            // next stop of a running link is what gets adopted: see `savesItself`.)
            $lower === 'saveconfig' => $this->saveConfig($value),
            // What only spells out wg-quick's default says nothing
            $lower === 'table' && strtolower($value) === 'auto' => $this->drop('Table'),
            $lower === 'fwmark' && in_array(strtolower($value), ['off', '0'], true) => $this->drop('FwMark'),
            $lower === 'table' => $this->block('Table'),
            $lower === 'fwmark' => $this->block('FwMark'),
            $lower === 'dns' => $this->block('DNS'),
            // Not named: what stands before a `=` is only a key where wg-quick knows it (the rest
            // of a key that was broken over two lines would be named here)
            default => $this->block('unknown settings'),
        };
    }

    private function peerLine(string $key, string $value): void
    {
        $lower = strtolower($key);
        $peer = &$this->peers[array_key_last($this->peers)];

        if ($lower === 'allowedips') {
            array_push($peer['allowed_ips'], ...array_values(array_filter(array_map('trim', explode(',', $value)), fn (string $entry) => $entry !== '')));
        } elseif (isset(self::PEER_KEYS[$lower])) {
            $this->once($peer[self::PEER_KEYS[$lower]], ['publickey' => 'PublicKey', 'presharedkey' => 'PresharedKey', 'endpoint' => 'Endpoint', 'persistentkeepalive' => 'PersistentKeepalive'][$lower], $value);
        } else {
            $this->block('unknown settings');
        }
    }

    private function saveConfig(string $value): void
    {
        $this->savesItself = $this->savesItself || strtolower($value) === 'true';
        $this->drop('SaveConfig');
    }

    /** A value there can only be one of: a second one is nothing the app's format has a place for. */
    private function once(?string &$slot, string $name, string $value): void
    {
        if ($slot !== null) {
            $this->block($name);

            return;
        }
        $slot = $value;
    }

    public function drop(string $what, int $lines = 1): void
    {
        $this->dropped[$what] = ($this->dropped[$what] ?? 0) + $lines;
    }

    public function block(string $what): void
    {
        if (! in_array($what, $this->blocking, true)) {
            $this->blocking[] = $what;
        }
    }
}
