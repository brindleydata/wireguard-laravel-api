<?php

return [
    'templates' => [
        // vpn link (network interface) template
        'link' => <<<CONF
            [Interface]
            Address = {address}
            SaveConfig = true
            PrivateKey = {privkey}
            ListenPort = {port}
            PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -d {subnets} -o {ifout} -j MASQUERADE;
            PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -d {subnets} -o {ifout} -j MASQUERADE;
        CONF,

        // single peer template (added to the server links)
        'peer' => <<<CONF
            [Peer]
            PublicKey = {pubkey}
            PresharedKey = {psk}
            AllowedIPs = {ip}
        CONF,

        // client-side configuration
        'client' => <<<CONF
            [Interface]
            PrivateKey = {privkey}

            [Peer]
            PublicKey = {pubkey}
            PresharedKey = {psk}
            AllowedIPs = {subnets}
            PersistentKeepalive = {keepalive}
        CONF,
    ],
];
