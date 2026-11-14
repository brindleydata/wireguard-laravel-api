<?php

use App\DTOs\PeerInfo;
use App\Exceptions\ConflictException;
use App\Exceptions\SystemException;
use Tests\Support\Rig;

/*
 * Service behaviour against a simulated Linux and macOS host (see Tests\Fakes\FakeHost).
 */

afterEach(fn () => Rig::cleanup());

it('runs a created link under its OS interface', function (string $os) {
    $rig = new Rig($os);

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    // wg-quick on macOS always runs a link as a fresh utunN
    $iface = $os === 'mac' ? 'utun4' : 'wg0';
    expect($rig->host->interfaceOf('wg0'))->toBe($iface)
        ->and($link->up)->toBeTrue()
        ->and($link->interface)->toBe($iface)
        ->and($link->address)->toBe('10.0.0.1/24')
        ->and($link->listen_port)->toBe(51820)
        ->and($rig->wg->isRunning('wg0'))->toBeTrue()
        ->and($rig->wg->listLinks())->toBe(['wg0']);
})->with('os');

it('reads a stopped link from its config', function (string $os) {
    $rig = new Rig($os);

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);

    expect($rig->host->interfaceOf('wg0'))->toBeNull()
        ->and($link->up)->toBeFalse()
        ->and($link->interface)->toBeNull()
        ->and($link->address)->toBe('10.0.0.1/24')
        ->and($rig->wg->listLinks())->toBe(['wg0']);
})->with('os');

it('applies peer changes on a running link live and saves them', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    $peer = $rig->wg->addPeer('wg0');

    expect($peer->allowed_ips)->toBe('10.0.0.2/32')
        ->and($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32'])
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32'])
        ->and($rig->shell->callsTo('sudo -n :helper peer-add :iface')[0]['bindings']['iface'])->toBe($rig->host->interfaceOf('wg0'))
        ->and($peer->client_config)->toContain('Endpoint = vpn.example.test:51820')
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBe($peer->client_config);

    $updated = $rig->wg->updatePeer('wg0', $peer->public_key, ['ip' => '10.0.0.9']);

    expect($updated->allowed_ips)->toBe('10.0.0.9/32')
        ->and($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.9/32'])
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.9/32'])
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain('Address = 10.0.0.9/32');

    $rig->wg->removePeer('wg0', $peer->public_key);

    expect($rig->host->runtimePeers('wg0'))->toBe([])
        ->and($rig->host->confPeers('wg0'))->toBe([])
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBeNull();
})->with('os');

it('only edits the config for peer changes on a stopped link', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);

    $first = $rig->wg->addPeer('wg0');
    $second = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $first->public_key, ['ip' => '10.0.0.9/32']);
    $rig->wg->removePeer('wg0', $second->public_key);

    expect($second->allowed_ips)->toBe('10.0.0.3/32')
        ->and($rig->host->confPeers('wg0'))->toBe([$first->public_key => '10.0.0.9/32'])
        ->and($rig->host->interfaceOf('wg0'))->toBeNull()
        ->and($rig->shell->callsTo('sudo -n :helper peer-add :iface'))->toBe([])
        ->and($rig->shell->callsTo('sudo -n :helper peer-remove :iface :pubkey'))->toBe([]);

    // Starting the link loads the saved peers
    $link = $rig->wg->updateLink('wg0', ['up' => true]);

    expect($link->up)->toBeTrue()
        ->and($rig->host->runtimePeers('wg0'))->toBe([$first->public_key => '10.0.0.9/32']);
})->with('os');

it('stops a deleted running link and removes its files', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true);
    $rig->wg->addPeer('wg0');

    $rig->wg->deleteLink('wg0');

    expect($rig->host->interfaces)->toBe([])
        ->and($rig->host->files())->toBe([], 'Config, client configs and the macOS name file are gone')
        ->and($rig->host->firewall)->toBe([])
        ->and($rig->host->enabledUnits)->toBe([])
        ->and($rig->wg->listLinks())->toBe([]);
})->with('os');

it('keeps the firewall rules in line with the link state', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    expect($rig->host->firewall)->not->toHaveKey('wg0');

    $rig->wg->updateLink('wg0', ['forward' => true]);
    expect($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => false]);

    $rig->wg->updateLink('wg0', ['nat' => true]);
    expect($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true]);

    $rig->wg->updateLink('wg0', ['up' => false]);
    expect($rig->host->interfaceOf('wg0'))->toBeNull()
        ->and($rig->host->firewall)->not->toHaveKey('wg0');

    // PostUp restores the saved state
    $rig->wg->updateLink('wg0', ['up' => true]);
    expect($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true]);

    $rig->wg->updateLink('wg0', ['forward' => false, 'nat' => false]);
    expect($rig->host->firewall)->not->toHaveKey('wg0');
})->with('os');

it('leaves no rules behind when stopping while turning them off', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true);

    // The rewritten config has no PostDown any more, so wg-quick alone would leave the rules
    $rig->wg->updateLink('wg0', ['up' => false, 'forward' => false, 'nat' => false]);

    expect($rig->host->interfaceOf('wg0'))->toBeNull()
        ->and($rig->host->firewall)->toBe([]);
})->with('os');

it('applies live firewall changes to the real interface', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    $rig->wg->updateLink('wg0', ['forward' => true, 'nat' => true]);

    expect($rig->shell->callsTo('sudo -n :helper firewall-up :link :iface')[0]['bindings'])
        ->toMatchArray(['link' => 'wg0', 'iface' => $os === 'mac' ? 'utun4' : 'wg0']);
})->with('os');

it('restarts the link with its peers when address and port change', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');

    $link = $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/16', 'port' => 51821]);

    expect($link->up)->toBeTrue()
        ->and($link->address)->toBe('10.0.0.1/16')
        ->and($link->listen_port)->toBe(51821)
        ->and($link->interface)->toBe($os === 'mac' ? 'utun5' : 'wg0')
        ->and($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32'])
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32']);
})->with('os');

it('rolls back a link that fails to start', function (string $os) {
    $rig = new Rig($os);
    $rig->host->failNextStart = true;

    expect(fn () => $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true))
        ->toThrow(SystemException::class, 'Failed to create link wg0');

    expect($rig->host->conf('wg0'))->toBeNull()
        ->and($rig->host->interfaces)->toBe([])
        ->and($rig->host->enabledUnits)->toBe([])
        ->and($rig->wg->listLinks())->toBe([]);
})->with('os');

it('lists unmanaged running interfaces once', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->host->addUnmanagedInterface('wg9');

    expect($rig->wg->listLinks())->toBe(['wg0', 'wg9']);
})->with('os');

it('hands configs and peers to the helper on stdin and keeps locks in the shared directory', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');

    // Secrets never appear on a command line or in a temp file
    foreach ($rig->shell->calls as $call) {
        expect($call['bound'])->not->toContain($peer->private_key)->not->toContain($peer->preshared_key);
    }
    expect($rig->shell->callsTo('sudo -n :helper conf-write :name')[0]['input'])->toContain('PrivateKey = ')
        ->and($rig->shell->callsTo('sudo -n :helper peer-add :iface')[0]['input'])->toContain("PresharedKey = {$peer->preshared_key}")
        ->and("{$rig->tmp}/locks/wg0.lock")->toBeFile();
})->with('os');

it('keeps peer client settings on the client side', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');

    $updated = $rig->wg->updatePeer('wg0', $peer->public_key, ['dns' => '1.1.1.1', 'allowed_ips' => '10.0.0.0/24']);

    // The server keeps routing only the peer's own address to it
    expect($updated->allowed_ips)->toBe('10.0.0.2/32')
        ->and($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32'])
        ->and($updated->client_config)->toContain('DNS = 1.1.1.1', 'AllowedIPs = 10.0.0.0/24');

    // Moving the peer keeps its client overrides
    $moved = $rig->wg->updatePeer('wg0', $peer->public_key, ['ip' => '10.0.0.7']);

    expect($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.7/32'])
        ->and($moved->client_config)->toContain('Address = 10.0.0.7/32', 'DNS = 1.1.1.1', 'AllowedIPs = 10.0.0.0/24');
})->with('os');

it('refreshes client configs on link changes but keeps peer overrides', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => '9.9.9.9']);

    $rig->wg->updateLink('wg0', ['port' => 51821, 'dns' => '1.1.1.1', 'keepalive' => 15]);

    expect($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain(
        'Endpoint = vpn.example.test:51821',
        'DNS = 1.1.1.1',
        'PersistentKeepalive = 15',
        'Address = 10.0.0.2/32',
    );
    expect($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain(
        'Endpoint = vpn.example.test:51821',
        'DNS = 9.9.9.9',
    );
})->with('os');

it('rejects invalid settings before running anything', function (array $settings) {
    $rig = new Rig('linux');

    expect(fn () => $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, ...$settings))
        ->toThrow(InvalidArgumentException::class);

    expect($rig->shell->calls)->toBe([]);
})->with([
    'dns with a line break' => [['dns' => "1.1.1.1\nPostUp = touch /tmp/pwned"]],
    'allowed_ips with a section' => [['allowed_ips' => "0.0.0.0/0\n[Interface]"]],
    'malformed allowed_ips' => [['allowed_ips' => '10.0.0.0/33']],
    'keepalive out of range' => [['keepalive' => 70000]],
    'ifout with shell syntax' => [['ifout' => 'eth0;id']],
    'a link-local IPv6 address' => [['address6' => 'fe80::1/64']],
    'an IPv6 prefix without an address' => [['address6' => 'fd12:3456:789a::/64']],
    'an IPv6 address with a line break' => [['address6' => "fd12::1/64\nPostUp = id"]],
    'an IPv6 prefix too small for the IPv4 subnet' => [['address6' => 'fd12::1/124']],
]);

it('only accepts a free single host in the subnet as a peer address', function (string $os, string $ip) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $taken = $rig->wg->addPeer('wg0');

    expect(fn () => $rig->wg->addPeer('wg0', $ip))->toThrow(InvalidArgumentException::class);

    expect($rig->host->runtimePeers('wg0'))->toBe([$taken->public_key => '10.0.0.2/32']);
})->with('os')->with([
    'a /24' => '10.0.0.5/24',
    "the link's own address" => '10.0.0.1',
    'the network address' => '10.0.0.0',
    'the broadcast address' => '10.0.0.255',
    'outside the subnet' => '10.0.1.5',
    'already taken' => '10.0.0.2',
]);

it('refuses a link that clashes with another link or interface', function (string $os, array $link, string $message) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    expect(fn () => $rig->wg->createLink(...$link))->toThrow(ConflictException::class, $message);
})->with('os')->with([
    'same port' => [['name' => 'wg1', 'ip' => '10.1.0.1/24', 'port' => 51820], 'Port 51820 is already used by link wg0'],
    'overlapping subnet' => [['name' => 'wg1', 'ip' => '10.0.0.129/25', 'port' => 51821], 'overlaps link wg0'],
    'enclosing subnet' => [['name' => 'wg1', 'ip' => '10.0.5.1/16', 'port' => 51821], 'overlaps link wg0'],
]);

it('refuses a link named after an existing network interface', function (string $os) {
    $rig = new Rig($os);
    $name = $os === 'mac' ? 'en0' : 'eth0';

    expect(fn () => $rig->wg->createLink($name, '10.1.0.1/24', 51821))
        ->toThrow(ConflictException::class, "A network interface named {$name} already exists");
})->with('os');

it('refuses to move a link onto another link\'s port or subnet', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821);

    expect(fn () => $rig->wg->updateLink('wg1', ['port' => 51820]))->toThrow(ConflictException::class, 'Port 51820')
        ->and(fn () => $rig->wg->updateLink('wg1', ['address' => '10.0.0.200/24']))->toThrow(ConflictException::class, 'overlaps link wg0')
        ->and($rig->wg->updateLink('wg1', ['port' => 51822])->listen_port)->toBe(51822);
});

it('refuses a new link address its peers would not fit in', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->addPeer('wg0'); // 10.0.0.2
    $rig->wg->addPeer('wg0', '10.0.0.200');

    expect(fn () => $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/25']))
        ->toThrow(InvalidArgumentException::class, 'Peer 10.0.0.200 would not fit the new address 10.0.0.1/25')
        ->and(fn () => $rig->wg->updateLink('wg0', ['address' => '10.0.0.2/24']))
        ->toThrow(InvalidArgumentException::class, 'Peer 10.0.0.2 would not fit')
        ->and($rig->wg->updateLink('wg0', ['address' => '10.0.0.1/16'])->address)->toBe('10.0.0.1/16');
})->with('os');

it('picks a free random port', function () {
    $rig = new Rig('linux');

    $first = $rig->wg->createLink('wg0', '10.0.0.1/24');
    $second = $rig->wg->createLink('wg1', '10.1.0.1/24');

    expect($first->listen_port)->toBeGreaterThanOrEqual(33000)->toBeLessThanOrEqual(65000)
        ->and($second->listen_port)->not->toBe($first->listen_port);
});

it('disables the unit of a stopped link when deleting it on Linux', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);
    $rig->host->enabledUnits[] = 'wg0'; // e.g. it failed to start at boot

    $rig->wg->deleteLink('wg0');

    expect($rig->host->enabledUnits)->toBe([])
        ->and($rig->host->files())->toBe([]);
});

it('reports live peer stats while the link runs', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $online = $rig->wg->addPeer('wg0');
    $never = $rig->wg->addPeer('wg0');
    $rig->host->setPeerStats('wg0', $online->public_key, '198.51.100.7:40122', time() - 30, 1048576, 2048);

    $peers = collect($rig->wg->getLink('wg0')->peers)->keyBy('public_key');

    expect($peers[$online->public_key])
        ->endpoint->toBe('198.51.100.7:40122')
        ->transfer_rx->toBe(1048576)
        ->transfer_tx->toBe(2048)
        ->and($peers[$online->public_key]->connected())->toBeTrue()
        ->and($peers[$online->public_key]->toArray()['latest_handshake_at'])->toMatch('/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/')
        ->and($peers[$never->public_key]->toArray())->toMatchArray([
            'endpoint' => null, 'latest_handshake_at' => null, 'connected' => false, 'transfer_rx' => 0, 'transfer_tx' => 0,
        ]);

    // Down: nothing live to report
    $rig->wg->updateLink('wg0', ['up' => false]);
    expect($rig->wg->getLink('wg0')->peers[0]->toArray())->toMatchArray([
        'endpoint' => null, 'latest_handshake_at' => null, 'connected' => null, 'transfer_rx' => null, 'transfer_tx' => null,
    ]);
})->with('os');

it('counts a peer as connected for 3 minutes after its last handshake', function () {
    $peer = fn (?int $handshake) => new PeerInfo('KEY', latest_handshake: $handshake, transfer_rx: 0, transfer_tx: 0);

    expect($peer(1000)->connected(now: 1000 + 179))->toBeTrue()
        ->and($peer(1000)->connected(now: 1000 + 180))->toBeFalse()
        ->and($peer(null)->connected(now: 1000))->toBeFalse()
        ->and((new PeerInfo('KEY'))->connected())->toBeNull();
});

it('treats creating an existing link as a conflict', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    expect(fn () => $rig->wg->createLink('wg0', '10.0.1.1/24', 51821))
        ->toThrow(ConflictException::class, 'Link already exists: wg0');
});

// ─── IPv6 ───────────────────────────────────────────────────────────

it('gives peers of a dual-stack link their IPv4 host number in the IPv6 prefix', function (string $os) {
    $rig = new Rig($os);

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, nat: true, address6: 'FD12:3456:789A::1/64');

    expect($link->address6)->toBe('fd12:3456:789a::1/64')
        ->and($rig->host->conf('wg0'))->toContain("# address6 = fd12:3456:789a::1/64\n", "Address = 10.0.0.1/24, fd12:3456:789a::1/64\n")
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => false, 'nat' => true, 'nat6' => 'fd12:3456:789a::1/64']);

    $peer = $rig->wg->addPeer('wg0');

    expect($peer->allowed_ips)->toBe('10.0.0.2/32, fd12:3456:789a::2/128')
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32, fd12:3456:789a::2/128'])
        ->and($rig->wg->getLink('wg0')->peers[0]->allowed_ips)->toBe('10.0.0.2/32, fd12:3456:789a::2/128')
        ->and($peer->client_config)->toContain("Address = 10.0.0.2/32, fd12:3456:789a::2/128\n", "AllowedIPs = 0.0.0.0/0, ::/0\n");

    $rig->wg->updatePeer('wg0', $peer->public_key, ['ip' => '10.0.0.9']);

    expect($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.9/32,fd12:3456:789a::9/128'])
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.9/32, fd12:3456:789a::9/128'])
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain("Address = 10.0.0.9/32, fd12:3456:789a::9/128\n");
})->with('os');

it('adds and removes IPv6 on an existing link, moving its peers along', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, nat: true, up: $up);
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $custom->public_key, ['allowed_ips' => '10.0.0.0/24']);

    $link = $rig->wg->updateLink('wg0', ['address6' => 'fd12::1/64']);

    expect($link->address6)->toBe('fd12::1/64')
        ->and($link->up)->toBe($up)
        ->and($rig->host->confPeers('wg0'))->toBe([
            $plain->public_key => '10.0.0.2/32, fd12::2/128',
            $custom->public_key => '10.0.0.3/32, fd12::3/128',
        ])
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("Address = 10.0.0.2/32, fd12::2/128\n", "AllowedIPs = 0.0.0.0/0, ::/0\n")
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain("Address = 10.0.0.3/32, fd12::3/128\n", "AllowedIPs = 10.0.0.0/24\n");
    if ($up) {
        expect($rig->host->runtimePeers('wg0'))->toBe([
            $plain->public_key => '10.0.0.2/32, fd12::2/128',
            $custom->public_key => '10.0.0.3/32, fd12::3/128',
        ])->and($rig->host->firewall['wg0']['nat6'])->toBe('fd12::1/64');
    }

    $link = $rig->wg->updateLink('wg0', ['address6' => null]);

    expect($link->address6)->toBeNull()
        ->and($rig->host->conf('wg0'))->not->toContain('fd12')
        ->and($rig->host->confPeers('wg0'))->toBe([$plain->public_key => '10.0.0.2/32', $custom->public_key => '10.0.0.3/32'])
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("Address = 10.0.0.2/32\n", "AllowedIPs = 0.0.0.0/0\n")
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain("AllowedIPs = 10.0.0.0/24\n");
    if ($up) {
        expect($rig->host->firewall['wg0'])->not->toHaveKey('nat6');
    }
})->with('os')->with(['running' => true, 'stopped' => false]);

it('moves peer IPv6 addresses with the IPv4 subnet', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.1.1/24', 51820, address6: 'fd12::1/64');
    $peer = $rig->wg->addPeer('wg0', '10.0.1.5');

    // 10.0.1.5 is host 5 of 10.0.1.0/24 but host 261 of 10.0.0.0/23
    $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/23']);

    expect($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.1.5/32, fd12::105/128'])
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain('Address = 10.0.1.5/32, fd12::105/128');
});

it('picks a random private /64 for address6=auto', function () {
    $rig = new Rig('linux');

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, address6: 'auto');

    expect($link->address6)->toMatch('/^fd[0-9a-f]{2}:[0-9a-f]{1,4}:[0-9a-f]{1,4}::1\/64$/')
        ->and($rig->wg->createLink('wg1', '10.1.0.1/24', 51821, address6: 'auto')->address6)->not->toBe($link->address6);
});

it('keeps peers off the link\'s own IPv6 address', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, address6: 'fd12::2/64');

    expect($rig->wg->addPeer('wg0')->allowed_ips)->toBe('10.0.0.3/32, fd12::3/128', 'Host 2 is the link\'s')
        ->and(fn () => $rig->wg->addPeer('wg0', '10.0.0.2'))->toThrow(InvalidArgumentException::class, "would get the link's own IPv6 address")
        ->and(fn () => $rig->wg->updateLink('wg0', ['address6' => 'fd12::3/64']))->toThrow(InvalidArgumentException::class, "Peer 10.0.0.3 would get the link's IPv6 address");
});

it('refuses overlapping IPv6 prefixes and prefixes too small for the IPv4 subnet', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, address6: 'fd12::1/64');

    expect(fn () => $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, address6: 'fd12::abcd/64'))->toThrow(ConflictException::class, 'Prefix fd12::abcd/64 overlaps link wg0')
        ->and(fn () => $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, address6: 'fd12::1/48'))->toThrow(ConflictException::class, 'overlaps link wg0')
        ->and(fn () => $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/8', 'address6' => 'fd13::1/120']))->toThrow(InvalidArgumentException::class, 'too small')
        ->and(fn () => $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/16']))->not->toThrow(Throwable::class)
        ->and($rig->wg->createLink('wg1', '10.1.0.1/24', 51821, address6: 'fd13::1/64')->address6)->toBe('fd13::1/64');
});

it('brackets an IPv6 endpoint in client configs', function () {
    $rig = new Rig('linux', '2001:db8::10');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    expect($rig->wg->addPeer('wg0')->client_config)->toContain("Endpoint = [2001:db8::10]:51820\n");
});

// ─── Peer names, disabled peers, networks behind peers ──────────────

it('labels peers, also across live changes and restarts', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    $alice = $rig->wg->addPeer('wg0', name: ' Алиса, phone ');
    $bob = $rig->wg->addPeer('wg0');

    expect($alice->name)->toBe('Алиса, phone')
        ->and($rig->host->conf('wg0'))->toContain("[Peer]\n# name = Алиса, phone\nPublicKey = {$alice->public_key}")
        ->and(array_map(fn (PeerInfo $p) => $p->name, $rig->wg->getLink('wg0')->peers))->toBe(['Алиса, phone', null]);

    $rig->wg->updatePeer('wg0', $bob->public_key, ['name' => 'Bob']);
    $rig->wg->updateLink('wg0', ['port' => 51821]); // restarts the link
    $rig->wg->updatePeer('wg0', $alice->public_key, ['name' => null]);

    expect(array_map(fn (PeerInfo $p) => $p->name, $rig->wg->getLink('wg0')->peers))->toBe([null, 'Bob'])
        ->and(fn () => $rig->wg->updatePeer('wg0', $bob->public_key, ['name' => "Bob\nPostUp = id"]))->toThrow(InvalidArgumentException::class);
})->with('os');

it('disables a peer without losing it, and enables it again', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: $up);
    $peer = $rig->wg->addPeer('wg0', name: 'laptop');
    $config = $peer->client_config;

    $disabled = $rig->wg->updatePeer('wg0', $peer->public_key, ['enabled' => false]);

    $shown = $rig->wg->getLink('wg0')->peers[0];
    expect($disabled->enabled)->toBeFalse()
        ->and($shown->enabled)->toBeFalse()
        ->and($shown->name)->toBe('laptop')
        ->and($shown->allowed_ips)->toBe('10.0.0.2/32')
        ->and($shown->connected())->toBeNull()
        ->and($rig->host->conf('wg0'))->toContain("# [Peer] disabled\n# name = laptop\n# PublicKey = {$peer->public_key}\n# PresharedKey = {$peer->preshared_key}\n# AllowedIPs = 10.0.0.2/32")
        ->and($rig->host->confPeers('wg0'))->toBe([], 'wg-quick loads no disabled peer')
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBe($config)
        ->and($rig->wg->addPeer('wg0')->allowed_ips)->toBe('10.0.0.3/32', 'Its address stays taken');
    if ($up) {
        expect($rig->host->runtimePeers('wg0'))->not->toHaveKey($peer->public_key);
    }

    $rig->wg->updatePeer('wg0', $peer->public_key, ['enabled' => true]);

    expect($rig->wg->getLink('wg0')->peers[0]->enabled)->toBeTrue()
        ->and($rig->host->confPeers('wg0'))->toHaveKey($peer->public_key)
        ->and($rig->host->conf('wg0'))->not->toContain('disabled');
    if ($up) {
        expect($rig->host->runtimePeers('wg0')[$peer->public_key])->toBe('10.0.0.2/32');
    }
})->with('os')->with(['running' => true, 'stopped' => false]);

it('never puts a disabled peer on the running interface', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $peer->public_key, ['enabled' => false]);
    $calls = count($rig->shell->calls);

    $rig->wg->updatePeer('wg0', $peer->public_key, ['ip' => '10.0.0.9', 'name' => 'moved']);
    $rig->wg->addPeer('wg0'); // rewrites the config from the live interface
    $rig->wg->removePeer('wg0', $peer->public_key);

    $live = array_column(array_slice($rig->shell->calls, $calls), 'command');
    expect($live)->not->toContain('sudo -n :helper peer-ips :iface :pubkey :ips')
        ->and($live)->not->toContain('sudo -n :helper peer-remove :iface :pubkey')
        ->and($rig->host->runtimePeers('wg0'))->not->toHaveKey($peer->public_key)
        ->and($rig->host->conf('wg0'))->not->toContain($peer->public_key);
});

it('routes networks behind a peer to it (site-to-site)', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, address6: 'fd12::1/64');
    $iface = $rig->host->interfaceOf('wg0');

    $router = $rig->wg->addPeer('wg0', name: 'branch', networks: '192.168.1.7/24, 2001:db8:1::/48');

    expect($router->networks)->toBe('192.168.1.0/24, 2001:db8:1::/48')
        ->and($router->allowed_ips)->toBe('10.0.0.2/32, fd12::2/128, 192.168.1.0/24, 2001:db8:1::/48')
        ->and($rig->host->runtimePeers('wg0')[$router->public_key])->toBe($router->allowed_ips)
        ->and($rig->wg->getLink('wg0')->peers[0]->networks)->toBe('192.168.1.0/24, 2001:db8:1::/48');
    if ($os === 'mac') {
        expect($rig->host->interfaceOf('wg0'))->not->toBe($iface, 'wg-quick restarted the link to route the networks');
    }

    // Moving the peer keeps them; changing them restarts the link; removing them too
    $rig->wg->updatePeer('wg0', $router->public_key, ['ip' => '10.0.0.9']);
    expect($rig->host->confPeers('wg0')[$router->public_key])->toBe('10.0.0.9/32, fd12::9/128, 192.168.1.0/24, 2001:db8:1::/48');

    $starts = count($rig->shell->callsTo('sudo -n :helper up :name'));
    $rig->wg->updatePeer('wg0', $router->public_key, ['networks' => '192.168.2.0/24']);
    expect($rig->host->runtimePeers('wg0')[$router->public_key])->toBe('10.0.0.9/32, fd12::9/128, 192.168.2.0/24')
        ->and($rig->shell->callsTo('sudo -n :helper up :name'))->toHaveCount($starts + 1);

    $rig->wg->updatePeer('wg0', $router->public_key, ['networks' => null]);
    expect($rig->host->confPeers('wg0')[$router->public_key])->toBe('10.0.0.9/32, fd12::9/128')
        ->and($rig->wg->getLink('wg0')->peers[0]->networks)->toBeNull();
})->with('os');

it('refuses networks that would take another route', function (string $networks, string $exception, string $message) {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->addPeer('wg0', name: 'branch', networks: '192.168.1.0/24');
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821);
    $rig->wg->addPeer('wg1', networks: '172.16.0.0/16');

    expect(fn () => $rig->wg->addPeer('wg0', networks: $networks))->toThrow($exception, $message);
})->with([
    'a default route' => ['0.0.0.0/0', InvalidArgumentException::class, 'default route'],
    'loopback' => ['127.0.0.0/8', InvalidArgumentException::class, 'reserved'],
    "the link's own subnet" => ['10.0.0.0/16', InvalidArgumentException::class, "the link's own addresses"],
    "another peer's network" => ['192.168.1.128/25', ConflictException::class, 'overlaps 192.168.1.0/24 of peer branch'],
    "another link's subnet" => ['10.1.0.0/24', ConflictException::class, 'of link wg1'],
    "a network behind another link's peer" => ['172.16.5.0/24', ConflictException::class, 'of link wg1'],
    'garbage' => ['192.168.9.0/24;id', InvalidArgumentException::class, 'Invalid allowed IP'],
]);

it('refuses a link subnet that a peer of another link routes', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->addPeer('wg0', networks: '192.168.1.0/24');

    expect(fn () => $rig->wg->createLink('wg1', '192.168.1.1/24', 51821))->toThrow(ConflictException::class, 'routed to a peer of link wg0');

    // Nor can a link grow over its own peers' networks
    $rig->wg->createLink('wg2', '172.20.0.1/24', 51822);
    $rig->wg->addPeer('wg2', networks: '172.21.0.0/16');
    expect(fn () => $rig->wg->updateLink('wg2', ['address' => '172.20.0.1/14']))->toThrow(InvalidArgumentException::class, '172.20.0.1/14 would overlap 172.21.0.0/16');
});
