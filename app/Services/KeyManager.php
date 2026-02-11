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

    public static function pubkeyToSafe(string $pubkey): string
    {
        return rtrim(strtr($pubkey, '+/', '-_'), '=');
    }

    public static function safeToPubkey(string $safe): string
    {
        return strtr($safe, '-_', '+/').str_repeat('=', (4 - strlen($safe) % 4) % 4);
    }
}
