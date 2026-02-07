<?php

namespace App\Services;

use RuntimeException;

class WireGuardSocket
{
    public function __construct(
        protected string $socketDir = '/var/run/wireguard',
    ) {}

    /**
     * List interfaces by scanning for .sock files in the socket directory.
     */
    public function listInterfaces(): array
    {
        $pattern = rtrim($this->socketDir, '/').'/*.sock';
        $files = glob($pattern);

        if ($files === false || $files === []) {
            return [];
        }

        return array_map(
            fn (string $path) => basename($path, '.sock'),
            $files,
        );
    }

    /**
     * Check if a socket file exists for the given interface.
     */
    public function socketExists(string $interface): bool
    {
        return file_exists($this->socketPath($interface));
    }

    /**
     * GET the current configuration and status of a WireGuard interface via UAPI.
     *
     * Returns: [
     *   'private_key' => hex, 'listen_port' => int, 'fwmark' => int,
     *   'public_key' => hex,
     *   'peers' => [ [ 'public_key' => hex, 'preshared_key' => hex|null,
     *                   'allowed_ips' => [...], 'endpoint' => str,
     *                   'last_handshake_time_sec' => int, 'rx_bytes' => int, 'tx_bytes' => int ], ... ]
     * ]
     */
    public function get(string $interface): array
    {
        $response = $this->request($interface, "get=1\n\n");

        return $this->parseGetResponse($response);
    }

    /**
     * SET interface configuration via UAPI.
     *
     * @param  array  $config  Interface-level settings: private_key (hex), listen_port, fwmark
     * @param  array  $peers  Peer configurations, each: public_key (hex), preshared_key (hex),
     *                        allowed_ips (array), remove (bool), replace_allowed_ips (bool),
     *                        endpoint (string)
     */
    public function set(string $interface, array $config = [], array $peers = []): void
    {
        $message = "set=1\n";

        if (isset($config['private_key'])) {
            $message .= "private_key={$config['private_key']}\n";
        }
        if (isset($config['listen_port'])) {
            $message .= "listen_port={$config['listen_port']}\n";
        }
        if (isset($config['fwmark'])) {
            $message .= "fwmark={$config['fwmark']}\n";
        }

        foreach ($peers as $peer) {
            if (! isset($peer['public_key'])) {
                throw new RuntimeException('Each peer must have a public_key');
            }
            $message .= "public_key={$peer['public_key']}\n";

            if (! empty($peer['remove'])) {
                $message .= "remove=true\n";

                continue;
            }

            if (isset($peer['preshared_key'])) {
                $message .= "preshared_key={$peer['preshared_key']}\n";
            }
            if (! empty($peer['replace_allowed_ips'])) {
                $message .= "replace_allowed_ips=true\n";
            }
            if (isset($peer['allowed_ips'])) {
                foreach ((array) $peer['allowed_ips'] as $ip) {
                    $message .= "allowed_ip={$ip}\n";
                }
            }
            if (isset($peer['endpoint'])) {
                $message .= "endpoint={$peer['endpoint']}\n";
            }
            if (isset($peer['persistent_keepalive_interval'])) {
                $message .= "persistent_keepalive_interval={$peer['persistent_keepalive_interval']}\n";
            }
        }

        $message .= "\n";

        $response = $this->request($interface, $message);
        $this->checkSetResponse($response);
    }

    /**
     * Convert a 64-char lowercase hex key to base64.
     */
    public static function hexToBase64(string $hex): string
    {
        return base64_encode(hex2bin($hex));
    }

    /**
     * Convert a base64 key to 64-char lowercase hex.
     */
    public static function base64ToHex(string $base64): string
    {
        return bin2hex(base64_decode($base64));
    }

    /**
     * Get the socket file path for an interface.
     */
    protected function socketPath(string $interface): string
    {
        return rtrim($this->socketDir, '/')."/{$interface}.sock";
    }

    /**
     * Send a UAPI request and return the raw response lines.
     */
    protected function request(string $interface, string $message): array
    {
        $socketPath = $this->socketPath($interface);

        if (! file_exists($socketPath)) {
            throw new RuntimeException("WireGuard socket not found: {$socketPath}");
        }

        $socket = @stream_socket_client(
            "unix://{$socketPath}",
            $errno,
            $errstr,
            5,
        );

        if ($socket === false) {
            throw new RuntimeException("Failed to connect to WireGuard socket {$socketPath}: [{$errno}] {$errstr}");
        }

        try {
            fwrite($socket, $message);

            $response = '';
            while (! feof($socket)) {
                $chunk = fread($socket, 8192);
                if ($chunk === false) {
                    break;
                }
                $response .= $chunk;
            }
        } finally {
            fclose($socket);
        }

        return explode("\n", rtrim($response, "\n"));
    }

    /**
     * Parse a GET response into a structured array.
     */
    protected function parseGetResponse(array $lines): array
    {
        $result = [
            'private_key' => null,
            'public_key' => null,
            'listen_port' => 0,
            'fwmark' => 0,
            'peers' => [],
        ];
        $currentPeer = null;

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line === 'errno=0') {
                continue;
            }

            if (str_starts_with($line, 'errno=')) {
                $errno = (int) substr($line, 6);
                if ($errno !== 0) {
                    throw new RuntimeException("UAPI get failed with errno={$errno}");
                }

                continue;
            }

            if (! str_contains($line, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $line, 2);

            if ($key === 'public_key') {
                // A new peer section begins
                if ($currentPeer !== null) {
                    $result['peers'][] = $currentPeer;
                }
                $currentPeer = [
                    'public_key' => $value,
                    'preshared_key' => null,
                    'allowed_ips' => [],
                    'endpoint' => null,
                    'last_handshake_time_sec' => 0,
                    'rx_bytes' => 0,
                    'tx_bytes' => 0,
                    'persistent_keepalive_interval' => 0,
                ];

                continue;
            }

            if ($currentPeer !== null) {
                // We're inside a peer section
                match ($key) {
                    'preshared_key' => $currentPeer['preshared_key'] = $this->isZeroKey($value) ? null : $value,
                    'allowed_ip' => $currentPeer['allowed_ips'][] = $value,
                    'endpoint' => $currentPeer['endpoint'] = $value,
                    'last_handshake_time_sec' => $currentPeer['last_handshake_time_sec'] = (int) $value,
                    'rx_bytes' => $currentPeer['rx_bytes'] = (int) $value,
                    'tx_bytes' => $currentPeer['tx_bytes'] = (int) $value,
                    'persistent_keepalive_interval' => $currentPeer['persistent_keepalive_interval'] = (int) $value,
                    default => null,
                };
            } else {
                // Interface-level fields
                match ($key) {
                    'private_key' => $result['private_key'] = $this->isZeroKey($value) ? null : $value,
                    'listen_port' => $result['listen_port'] = (int) $value,
                    'fwmark' => $result['fwmark'] = (int) $value,
                    default => null,
                };
            }
        }

        // Don't forget the last peer
        if ($currentPeer !== null) {
            $result['peers'][] = $currentPeer;
        }

        return $result;
    }

    /**
     * Check that a SET response indicates success (errno=0).
     */
    protected function checkSetResponse(array $lines): void
    {
        foreach ($lines as $line) {
            $line = trim($line);
            if (str_starts_with($line, 'errno=')) {
                $errno = (int) substr($line, 6);
                if ($errno !== 0) {
                    throw new RuntimeException("UAPI set failed with errno={$errno}");
                }

                return;
            }
        }

        throw new RuntimeException('UAPI set response missing errno');
    }

    /**
     * Check if a hex key is all zeros (meaning "not set").
     */
    protected function isZeroKey(string $hex): bool
    {
        return $hex === str_repeat('0', 64);
    }
}
