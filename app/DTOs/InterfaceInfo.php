<?php

namespace App\DTOs;

class InterfaceInfo
{
    /**
     * @param  PeerInfo[]  $peers
     * @param  string|null  $dns  the link's own client settings, each null where the fixed default
     *                            applies: DNS, keepalive, and ($allowed_ips) what its clients route
     */
    public function __construct(
        public readonly string $name,
        public readonly string $public_key,
        public readonly int $listen_port,
        public readonly string $address,
        public readonly string $ifout,
        public readonly bool $forward = false,
        public readonly bool $nat = false,
        public readonly bool $up = true,
        public readonly array $peers = [],
        public readonly ?string $interface = null, // OS interface while running (utunN on macOS)
        public readonly ?string $address6 = null,  // IPv6 address and prefix of a dual-stack link
        public readonly ?string $dns = null,
        public readonly ?int $keepalive = null,
        public readonly ?string $allowed_ips = null,
        public readonly ?int $mtu = null,  // the link's own MTU, for its interface and its clients; null: wg-quick's
        public readonly ?string $firewall = null,  // 'ok' or 'missing' for a running link with forward or NAT; else null
        public readonly bool $inbound = false,  // forwarding into the tunnel takes connections that start outside, not only replies
        public readonly bool $allow_default_route = false,  // its peers may route a default route (as far as the server allows)
        public readonly bool $allow_own_networks = false,  // its peers may route networks holding the server's own addresses (likewise)
        public readonly ?string $endpoint = null,  // where its clients connect: host, or host:port; null: detected when a config is built
    ) {}

    /** A copy with some properties replaced. */
    public function with(mixed ...$changes): static
    {
        return new static(...[...get_object_vars($this), ...$changes]);
    }

    /**
     * What the link's clients get instead of the fixed defaults, unless a peer has its own.
     *
     * @return array{dns: ?string, keepalive: ?int, allowed_ips: ?string}
     */
    public function clientSettings(): array
    {
        return ['dns' => $this->dns, 'keepalive' => $this->keepalive, 'allowed_ips' => $this->allowed_ips];
    }

    public function toArray(): array
    {
        return [
            'name' => $this->name,
            'interface' => $this->interface,
            'public_key' => $this->public_key,
            'listen_port' => $this->listen_port,
            'endpoint' => $this->endpoint,
            'address' => $this->address,
            'address6' => $this->address6,
            'ifout' => $this->ifout,
            'mtu' => $this->mtu,
            'forward' => $this->forward,
            'nat' => $this->nat,
            'inbound' => $this->inbound,
            'allow_default_route' => $this->allow_default_route,
            'allow_own_networks' => $this->allow_own_networks,
            'firewall' => $this->firewall,
            'up' => $this->up,
            'client' => $this->clientSettings(),
            'peers' => array_map(fn (PeerInfo $p) => $p->toArray(), $this->peers),
        ];
    }
}
