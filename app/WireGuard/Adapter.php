<?php

namespace App\WireGuard;

class Adapter
{
    public $interface;
    public $port;
    public $subnet;
    public $pubkey;
    public $privkey;
    public $peers;

    public function __construct(?array $args)
    {
        $this->interface = $args['interface'] ?? null;
        $this->public_key = $args['public_key'] ?? null;
        $this->private_key = $args['private_key'] ?? null;
        $this->listen_port = $args['listen_port'] ?? null;
        $this->vpn_address = $args['vpn_address'] ?? null;
        $this->peers = $args['peers'] ?? [];
    }
}
