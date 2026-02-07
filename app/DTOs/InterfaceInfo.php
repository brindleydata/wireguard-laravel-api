<?php

namespace App\DTOs;

class InterfaceInfo
{
    /**
     * @param  PeerInfo[]  $peers
     */
    public function __construct(
        public readonly string $name,
        public readonly string $public_key,
        public readonly string $private_key,
        public readonly int $listen_port,
        public readonly string $address,
        public readonly string $ifout,
        public readonly array $peers = [],
    ) {}

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'public_key' => $this->public_key,
            'private_key' => $this->private_key,
            'listen_port' => $this->listen_port,
            'address' => $this->address,
            'ifout' => $this->ifout,
            'peers' => array_map(fn (PeerInfo $p) => $p->toArray(), $this->peers),
        ];
    }
}
