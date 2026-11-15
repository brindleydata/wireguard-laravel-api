<?php

namespace App\Services;

class KeyManager
{
    public function genkey(): string
    {
        $key = random_bytes(32);

        // X25519 clamping
        $key[0] = chr(ord($key[0]) & 248);
        $key[31] = chr((ord($key[31]) & 127) | 64);

        return base64_encode($key);
    }

    public function genpsk(): string
    {
        return base64_encode(random_bytes(32));
    }

    public function pubkey(string $privkey): string
    {
        return base64_encode(\sodium_crypto_scalarmult_base(base64_decode($privkey)));
    }

    /** A WireGuard key as `wg` prints it: 32 bytes in base64. */
    public static function isKey(string $key): bool
    {
        return preg_match('#^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$#', $key) === 1;
    }

    /**
     * A public key as `wg` prints it, from either form it is written in: that one, or the
     * URL-safe one of the API's routes.
     */
    public static function normalize(string $key): string
    {
        return self::safeToPubkey(self::pubkeyToSafe($key));
    }

    public static function pubkeyToSafe(string $pubkey): string
    {
        return rtrim(strtr($pubkey, '+/', '-_'), '=');
    }

    public static function safeToPubkey(string $safe): string
    {
        return strtr($safe, '-_', '+/').str_repeat('=', (4 - strlen($safe) % 4) % 4);
    }
}
