<?php

namespace App\Services;

use InvalidArgumentException;

/**
 * Backups of every link: configs with all their keys, client configs, whether each link ran.
 *
 * A backup file is JSON: the key-derivation parameters (Argon2id), a nonce and the payload
 * encrypted with libsodium's secretbox under a key derived from the admin's passphrase. Without
 * the passphrase it can't be restored, on this server or any other.
 */
class Backup
{
    public const FORMAT = 'wgla-backup';

    public const MIN_PASSPHRASE = 12;

    public function __construct(
        protected WireGuard $wg,
        protected ConfigBuilder $configBuilder,
        protected array $config = [],
        protected string $appVersion = 'dev',
    ) {}

    /** @return array{format: string, version: int, created_at: string, app_version: string, hostname: ?string, links: array} */
    public function create(): array
    {
        return [
            'format' => self::FORMAT,
            'version' => 1,
            'created_at' => gmdate('Y-m-d\TH:i:s\Z'),
            'app_version' => $this->appVersion,
            'hostname' => $this->config['hostname'] ?? null,
            'links' => $this->wg->exportLinks(),
        ];
    }

    public function encrypt(array $payload, string $passphrase): string
    {
        if (strlen($passphrase) < self::MIN_PASSPHRASE) {
            throw new InvalidArgumentException('The passphrase must be at least '.self::MIN_PASSPHRASE.' characters.');
        }

        $salt = random_bytes(SODIUM_CRYPTO_PWHASH_SALTBYTES);
        $ops = SODIUM_CRYPTO_PWHASH_OPSLIMIT_MODERATE;
        $mem = SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
        $nonce = random_bytes(SODIUM_CRYPTO_SECRETBOX_NONCEBYTES);

        $key = $this->key($passphrase, $salt, $ops, $mem);
        $ciphertext = sodium_crypto_secretbox(json_encode($payload, JSON_THROW_ON_ERROR), $nonce, $key);
        sodium_memzero($key);

        return json_encode([
            'format' => self::FORMAT,
            'version' => 1,
            'kdf' => ['algorithm' => 'argon2id13', 'ops' => $ops, 'mem' => $mem, 'salt' => base64_encode($salt)],
            'nonce' => base64_encode($nonce),
            'ciphertext' => base64_encode($ciphertext),
        ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR)."\n";
    }

    public function decrypt(string $document, string $passphrase): array
    {
        $file = json_decode($document, true);
        if (! is_array($file) || ($file['format'] ?? null) !== self::FORMAT || ($file['version'] ?? null) !== 1) {
            throw new InvalidArgumentException('Not a WireGuard API backup file.');
        }

        $kdf = $file['kdf'] ?? [];
        $ops = (int) ($kdf['ops'] ?? 0);
        $mem = (int) ($kdf['mem'] ?? 0);
        // The file says how hard to derive the key; don't let a crafted one exhaust the machine
        if (($kdf['algorithm'] ?? null) !== 'argon2id13' || $ops < 1 || $ops > SODIUM_CRYPTO_PWHASH_OPSLIMIT_SENSITIVE
            || $mem < SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE || $mem > SODIUM_CRYPTO_PWHASH_MEMLIMIT_SENSITIVE) {
            throw new InvalidArgumentException('The backup uses unsupported encryption settings.');
        }

        $salt = base64_decode((string) ($kdf['salt'] ?? ''), true);
        $nonce = base64_decode((string) ($file['nonce'] ?? ''), true);
        $ciphertext = base64_decode((string) ($file['ciphertext'] ?? ''), true);
        if ($salt === false || strlen($salt) !== SODIUM_CRYPTO_PWHASH_SALTBYTES || $nonce === false
            || strlen($nonce) !== SODIUM_CRYPTO_SECRETBOX_NONCEBYTES || $ciphertext === false) {
            throw new InvalidArgumentException('The backup file is damaged.');
        }

        $key = $this->key($passphrase, $salt, $ops, $mem);
        $json = sodium_crypto_secretbox_open($ciphertext, $nonce, $key);
        sodium_memzero($key);
        if ($json === false) {
            throw new InvalidArgumentException('Wrong passphrase, or the backup file is damaged.');
        }

        $payload = json_decode($json, true);
        if (! is_array($payload) || ! is_array($payload['links'] ?? null)) {
            throw new InvalidArgumentException('The backup file is damaged.');
        }
        foreach ($payload['links'] as $name => $link) {
            if (! is_string($name) || ! is_string($link['conf'] ?? null) || ! is_array($link['clients'] ?? null)) {
                throw new InvalidArgumentException('The backup file is damaged.');
            }
        }

        return $payload;
    }

    /**
     * What's in a backup, per link.
     *
     * @return array<string, array{port: int, address: string, up: bool, peers: int, clients: int}>
     */
    public function links(array $payload): array
    {
        $links = [];
        foreach ($payload['links'] as $name => $link) {
            $parsed = $this->configBuilder->parseConfContent($link['conf']);
            $links[$name] = [
                'port' => (int) ($parsed['interface']['ListenPort'] ?? 0),
                'address' => $parsed['metadata']['address'] ?? $parsed['interface']['Address'] ?? '',
                'up' => (bool) ($link['up'] ?? false),
                'peers' => count($parsed['peers']),
                'clients' => count($link['clients']),
            ];
        }

        return $links;
    }

    /**
     * Why a backed-up link can't be restored next to the links already here (empty: it can).
     *
     * @param  list<string>  $ignore  links that will be replaced
     * @return list<string>
     */
    public function clashes(array $payload, string $name, array $ignore = []): array
    {
        $link = $this->links($payload)[$name];

        return $this->wg->findClashes($name, $link['port'], $link['address'], $ignore);
    }

    /**
     * Restore the chosen links: 'restore' (new here), 'replace' (delete the existing one first)
     * or 'skip'.
     *
     * @param  array<string, string>  $choices
     * @return array{restored: list<string>, skipped: list<string>, ifout: array<string, array{0: ?string, 1: string}>, clients: int, hostname: ?string, hostname_changed: bool}
     */
    public function restore(array $payload, array $choices): array
    {
        $report = ['restored' => [], 'skipped' => [], 'ifout' => [], 'clients' => 0];

        foreach ($payload['links'] as $name => $link) {
            $choice = $choices[$name] ?? 'skip';
            if ($choice === 'skip') {
                $report['skipped'][] = $name;

                continue;
            }
            if ($choice === 'replace') {
                $this->wg->deleteLink($name);
            }

            $result = $this->wg->restoreLink($name, $link['conf'], $link['clients'], (bool) ($link['up'] ?? false));
            $report['restored'][] = $name;
            $report['clients'] += $result['clients'];
            if ($result['ifout'] !== null) {
                $report['ifout'][$name] = $result['ifout'];
            }
        }

        $hostname = $this->config['hostname'] ?? null;

        return [...$report, 'hostname' => $hostname, 'hostname_changed' => ($payload['hostname'] ?? null) !== $hostname];
    }

    protected function key(string $passphrase, string $salt, int $ops, int $mem): string
    {
        return sodium_crypto_pwhash(SODIUM_CRYPTO_SECRETBOX_KEYBYTES, $passphrase, $salt, $ops, $mem, SODIUM_CRYPTO_PWHASH_ALG_ARGON2ID13);
    }
}
