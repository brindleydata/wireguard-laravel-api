<?php

namespace App\DTOs;

class PeerInfo
{
    public function __construct(
        public readonly string $publicKey,
        public readonly ?string $presharedKey = null,
        public readonly ?string $allowedIps = null,
        public readonly ?string $privateKey = null,
        public readonly ?string $clientConfig = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'public_key' => $this->publicKey,
            'preshared_key' => $this->presharedKey,
            'allowed_ips' => $this->allowedIps,
        ];

        if ($this->privateKey !== null) {
            $data['private_key'] = $this->privateKey;
        }

        if ($this->clientConfig !== null) {
            $data['client_config'] = $this->clientConfig;
        }

        return $data;
    }
}
