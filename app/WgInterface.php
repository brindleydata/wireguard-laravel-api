<?php

namespace App;

class WgInterface
{
    public $interface;
    public $public_key;
    public $private_key;
    public $listen_port;
    public $vpn_address;
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
