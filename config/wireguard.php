<?php

return [
    'api_key' => env('API_KEY'),

    // Root helper installed from bin/wgla-helper: the one command sudoers allows (see wg:help)
    'helper' => env('WIREGUARD_HELPER', '/usr/local/sbin/wgla-helper'),

    // The user the API runs as (set by wg:install). The wg:* link/peer commands must run as it too.
    'web_user' => env('WGLA_WEB_USER'),

    'ip_service' => env('IP_SERVICE', 'http://ifconfig.me/ip'),
    'hostname' => env('WIREGUARD_HOSTNAME'),

    'templates' => [
        // Client-side configuration template
        'client' => <<<'CONF'
[Interface]
PrivateKey = {privkey}
Address = {address}
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
