<?php

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
        ->and($rig->shell->callsTo('sudo wg addconf :iface /dev/stdin')[0]['bindings']['iface'])->toBe($rig->host->interfaceOf('wg0'))
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
        ->and($rig->shell->callsTo('sudo wg addconf :iface /dev/stdin'))->toBe([])
        ->and($rig->shell->callsTo('sudo wg set :iface peer :pubkey remove'))->toBe([]);

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
        ->and($rig->host->files)->toBe([], 'Config, client configs and the macOS name file are gone')
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

it('targets the utun interface in the macOS link anchor', function () {
    $rig = new Rig('mac');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    $rig->wg->updateLink('wg0', ['forward' => true, 'nat' => true]);

    expect($rig->host->anchors['wg/wg0'])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\npass in on utun4 all\npass out on utun4 all\n");
});

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

it('stages files privately and keeps locks in the shared directory', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->addPeer('wg0');

    expect($rig->host->stagedModes)->not->toBeEmpty()
        ->and(array_values(array_unique($rig->host->stagedModes)))->toBe(['0600'])
        ->and(glob("{$rig->tmp}/staging/*"))->toBe([], 'Staging files are removed')
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

it('treats creating an existing link as a conflict', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    expect(fn () => $rig->wg->createLink('wg0', '10.0.1.1/24', 51821))
        ->toThrow(ConflictException::class, 'Link already exists: wg0');
});
