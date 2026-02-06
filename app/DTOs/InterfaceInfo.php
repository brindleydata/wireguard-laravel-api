<?php

namespace App\DTOs;

class InterfaceInfo
{
    /**
     * @param  PeerInfo[]  $peers
     */
    public function __construct(
        public readonly string $name,
        public readonly string $publicKey,
        public readonly string $privateKey,
        public readonly int $listenPort,
        public readonly string $address,
        public readonly string $ifout,
        public readonly array $peers = [],
    ) {}

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'public_key' => $this->publicKey,
            'private_key' => $this->privateKey,
            'listen_port' => $this->listenPort,
            'address' => $this->address,
            'ifout' => $this->ifout,
            'peers' => array_map(fn (PeerInfo $p) => $p->toArray(), $this->peers),
        ];
    }
}
