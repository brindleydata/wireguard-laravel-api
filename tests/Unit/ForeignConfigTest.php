<?php

use App\Services\ForeignConfig;

/*
 * Reading a wg-quick config the app didn't write, line by line: what it holds, what an adoption
 * would drop, and what it has no place for. (What the values are worth is WireGuard::adoptLink()'s
 * to say: AdoptionTest.)
 */

const FOREIGN_KEY = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=';

it('accounts for every line of a config', function () {
    $config = ForeignConfig::parse(implode("\r\n", [
        '# wg0, the office',
        '# ifout = eth1',
        '[Interface]',
        'Address = 10.0.0.1/24, fd00::1/64',
        'Address=10.0.1.1/24',
        'PrivateKey = '.FOREIGN_KEY,
        'ListenPort = 51820   # as ever',
        'MTU = 1400',
        'PostUp = iptables -A FORWARD -i %i -j ACCEPT # opens it',
        'PostUp = sysctl -w net.ipv4.ip_forward=1',
        'PreDown = logger down',
        '',
        '[Peer]',
        '# name = laptop',
        '# bob\'s',
        'PublicKey = '.FOREIGN_KEY,
        'PresharedKey = '.FOREIGN_KEY,
        'AllowedIPs = 10.0.0.2/32',
        'AllowedIPs = 192.168.1.0/24,192.168.2.0/24',
        'Endpoint = [2001:db8::7]:51820',
        'PersistentKeepalive = 25',
    ]));

    expect($config->privateKey)->toBe(FOREIGN_KEY)
        ->and($config->listenPort)->toBe('51820')
        ->and($config->mtu)->toBe('1400')
        ->and($config->addresses)->toBe(['10.0.0.1/24', 'fd00::1/64', '10.0.1.1/24'])
        ->and($config->metadata)->toBe(['ifout' => 'eth1'])
        ->and($config->peers)->toBe([[
            'public_key' => FOREIGN_KEY, 'preshared_key' => FOREIGN_KEY, 'allowed_ips' => ['10.0.0.2/32', '192.168.1.0/24', '192.168.2.0/24'],
            'endpoint' => '[2001:db8::7]:51820', 'persistent_keepalive' => '25', 'enabled' => true,
            'name' => 'laptop', 'dns' => null, 'keepalive' => null, 'client_allowed_ips' => null,
        ]])
        // By key, with how many lines: never what a line says
        ->and($config->dropped)->toBe(['comments' => 4, 'PostUp' => 2, 'PreDown' => 1])
        ->and($config->blocking)->toBe([])
        ->and($config->savesItself)->toBeFalse();
});

it('names what it has no place for, once each, and never what it says', function () {
    $config = ForeignConfig::parse(implode("\n", [
        'stray = line',
        '[Interface]',
        'PrivateKey = '.FOREIGN_KEY,
        'PrivateKey = '.FOREIGN_KEY,
        'ListenPort = 51820',
        'ListenPort = 51821',
        'Table = off',
        'Table = 1234',
        'DNS = 10.0.0.53',
        'FwMark = 0xca6c',
        'ThisIsAKeyNobodyKnowsAndItIsVeryLongIndeed = 1',
        'just some words',
        '[Peer]',
        'PublicKey = '.FOREIGN_KEY,
        'PublicKey = '.FOREIGN_KEY,
        'Weight = 3',
        '[Interface]',
    ]));

    expect($config->blocking)->toBe(['other lines', 'PrivateKey', 'ListenPort', 'Table', 'DNS', 'FwMark', 'unknown settings', 'PublicKey', 'a second [Interface]'])
        ->and(implode(' ', $config->blocking))->not->toContain('10.0.0.53')->not->toContain('0xca6c');
});

it('names no key it does not know: what stands before a = may be the rest of a secret', function () {
    // A key that was broken over two lines: its second line reads as `<43 characters> =`
    $config = ForeignConfig::parse("[Interface]\nPrivateKey =\n".FOREIGN_KEY."\nListenPort = 51820\n[Peer]\nPresharedKey =\n".FOREIGN_KEY."\n");

    expect($config->blocking)->toBe(['unknown settings'])
        ->and(implode(' ', $config->blocking))->not->toContain(substr(FOREIGN_KEY, 0, 8));
});

it('drops what only spells out a default, and knows a config wg-quick saves itself', function () {
    $config = ForeignConfig::parse("[Interface]\nTable = AUTO\nFwMark = off\nSaveConfig = TRUE\nsaveconfig = false\n");

    expect($config->dropped)->toBe(['Table' => 1, 'FwMark' => 1, 'SaveConfig' => 2])
        ->and($config->savesItself)->toBeTrue()
        ->and($config->blocking)->toBe([])
        ->and(ForeignConfig::parse("[Interface]\nSaveConfig = false\n")->savesItself)->toBeFalse()
        ->and(ForeignConfig::parse("[Peer]\nPublicKey = ".FOREIGN_KEY."\n")->blocking)->toBe(['no [Interface]']);
});

it('reads what the app itself wrote as the app\'s: settings, a peer it disabled, its own hooks', function () {
    $config = ForeignConfig::parse(implode("\n", [
        '# address = 10.0.0.1/24',
        '# ifout = eth0',
        '# forward = true',
        '# destinations = 10.20.0.0/16',
        '# format = 2',
        '# dns = 9.9.9.9',
        '# owner = me',
        '[Interface]',
        'Address = 10.0.0.1/24',
        'PrivateKey = '.FOREIGN_KEY,
        'ListenPort = 51820',
        'PostUp = /usr/local/sbin/wgla-helper firewall-up %i %i',
        'PostDown = /opt/old/wgla-helper firewall-down %I',
        '',
        '[Peer]',
        '# name = laptop',
        '# dns = 1.1.1.1',
        '# keepalive = 0',
        '# allowed_ips = 10.0.0.0/24',
        'PublicKey = '.FOREIGN_KEY,
        'AllowedIPs = 10.0.0.2/32',
        '',
        '# [Peer] disabled',
        '# name = old phone',
        '# PublicKey = '.FOREIGN_KEY,
        '# AllowedIPs = 10.0.0.3/32',
        '# remember to delete it',
        '# Note = of mine',
    ]));

    expect($config->metadata)->toBe(['ifout' => 'eth0', 'forward' => 'true', 'destinations' => '10.20.0.0/16', 'dns' => '9.9.9.9'])
        ->and($config->peers[0])->toMatchArray(['name' => 'laptop', 'dns' => '1.1.1.1', 'keepalive' => '0', 'client_allowed_ips' => '10.0.0.0/24', 'enabled' => true])
        ->and($config->peers[1])->toMatchArray(['name' => 'old phone', 'public_key' => FOREIGN_KEY, 'allowed_ips' => ['10.0.0.3/32'], 'enabled' => false])
        // The helper's own hooks are written anew, wherever the helper was: only what isn't the app's is dropped
        ->and($config->dropped)->toBe(['comments' => 3])
        ->and($config->blocking)->toBe([]);

    // A line of a disabled peer that isn't commented out belongs to whatever section wg sees there
    expect(ForeignConfig::parse("[Interface]\n# [Peer] disabled\n# PublicKey = ".FOREIGN_KEY."\nAllowedIPs = 10.0.0.3/32\n")->blocking)->toBe(['other lines']);
});
