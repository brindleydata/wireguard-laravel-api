<?php

namespace App\DTOs;

class PeerInfo
{
    public function __construct(
        public readonly string $public_key,
        public readonly ?string $preshared_key = null,
        public readonly ?string $allowed_ips = null,
        public readonly ?string $private_key = null,
        public readonly ?string $client_config = null,
    ) {}

    public function toArray(): array
    {
        $data = [
            'public_key' => $this->public_key,
            'preshared_key' => $this->preshared_key,
            'allowed_ips' => $this->allowed_ips,
        ];

        if ($this->private_key !== null) {
            $data['private_key'] = $this->private_key;
        }

        if ($this->client_config !== null) {
            $data['client_config'] = $this->client_config;
        }

        return $data;
    }
}
