<?php

return [
    'api_key' => env('API_KEY'),
    'ip_service' => env('IP_SERVICE', 'http://ifconfig.me/ip'),
    'hostname' => env('WIREGUARD_HOSTNAME'),
    'default_dns' => env('WIREGUARD_DNS', '8.8.8.8'),
    'default_keepalive' => (int) env('WIREGUARD_KEEPALIVE', 25),
    'allowed_ips' => env('WIREGUARD_ALLOWED_IPS', '0.0.0.0/0'),

    'templates' => [
        // Client-side configuration template
        'client' => <<<'CONF'
[Interface]
PrivateKey = {privkey}
Address = {ip}/32
DNS = {dns}

[Peer]
PublicKey = {pubkey}
PresharedKey = {psk}
AllowedIPs = {subnets}
Endpoint = {endpoint}
PersistentKeepalive = {keepalive}
CONF,
    ],
];
