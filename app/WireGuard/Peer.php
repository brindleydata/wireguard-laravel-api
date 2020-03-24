<?php

namespace App\WireGuard;

class Peer
{
    public $private_key;
    public $vpn_address;
    public $dns;

    public $preshared_key;
    public $remote_public_key;
    public $remote_allowed_ips;
    public $remote_endpoint;
    public $persistent_keepalive;

    public function __construct(?array $args)
    {
        $this->private_key = $args['private_key'] ?? null;
        $this->vpn_address = $args['vpn_address'] ?? null;
        $this->dns = $args['dns'] ?? null;
        $this->preshared_key = $args['preshared_key'] ?? null;
        $this->remote_public_key = $args['remote_public_key'] ?? null;
        $this->remote_allowed_ips = $args['remote_allowed_ips'] ?? null;
        $this->remote_endpoint = $args['remote_endpoint'] ?? null;
        $this->persistent_keepalive = $args['persistent_keepalive'] ?? null;
    }
}
