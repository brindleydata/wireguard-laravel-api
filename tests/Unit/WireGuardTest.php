<?php

use App\DTOs\PeerInfo;
use App\Exceptions\ConflictException;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Services\ConfigBuilder;
use App\Services\IpAllocator;
use App\Services\KeyManager;
use App\Services\Os\LinuxDriver;
use App\Services\WireGuard;
use App\Validation\WireGuardValidator;
use Tests\Fakes\CommandFailed;
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

it('undoes a link change that the link does not start with', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true);
    $peer = $rig->wg->addPeer('wg0');
    $conf = $rig->host->conf('wg0');
    $rig->host->failNextStart = true; // e.g. another program has the new port

    expect(fn () => $rig->wg->updateLink('wg0', ['port' => 51999, 'dns' => '9.9.9.9']))
        ->toThrow(SystemException::class, 'The change to link wg0 could not be applied and was undone: wg-quick: failed to start wg0');

    // Up again as it was, config and client configs untouched
    expect($rig->wg->getLink('wg0'))->up->toBeTrue()->listen_port->toBe(51820)
        ->and($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32'])
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => false])
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBe($peer->client_config);
})->with('os');

it('leaves a stopped link stopped when it does not start', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);
    $conf = $rig->host->conf('wg0');
    $rig->host->failNextStart = true;

    expect(fn () => $rig->wg->updateLink('wg0', ['up' => true, 'port' => 51999]))->toThrow(SystemException::class, 'was undone');

    expect($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->host->interfaces)->toBe([])
        ->and($rig->host->enabledUnits)->toBe([], 'It would start at the next boot otherwise');
})->with('os');

it('says so when undoing a failed change fails too', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->shell->on('sudo -n :helper up :name', fn () => throw new CommandFailed('wg-quick: no such device'));

    expect(fn () => $rig->wg->updateLink('wg0', ['port' => 51999]))
        ->toThrow(SystemException::class, 'could not be applied, and undoing it failed too (check the link with wg:link wg0): wg-quick: no such device');

    // Down, but with the config it had
    expect($rig->host->conf('wg0'))->toContain('ListenPort = 51820');
});

it('takes back networks behind a peer that the link does not start with', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $first = $rig->wg->addPeer('wg0');
    $conf = $rig->host->conf('wg0');

    // wg-quick can't route them, say: the link would stay down for every peer
    $rig->host->failNextStart = true;
    expect(fn () => $rig->wg->addPeer('wg0', networks: '192.168.1.0/24'))->toThrow(SystemException::class, 'was undone');

    expect($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->host->runtimePeers('wg0'))->toBe([$first->public_key => '10.0.0.2/32'])
        ->and($rig->host->clients)->toHaveCount(1, 'No client config for a peer that was not added');

    $rig->host->failNextStart = true;
    expect(fn () => $rig->wg->updatePeer('wg0', $first->public_key, ['networks' => '192.168.1.0/24', 'name' => 'branch']))->toThrow(SystemException::class, 'was undone');

    expect($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->host->runtimePeers('wg0'))->toBe([$first->public_key => '10.0.0.2/32'])
        ->and($rig->wg->getLink('wg0')->peers[0])->name->toBeNull()->networks->toBeNull();
})->with('os');

it('fails instead of taking a running link for a stopped one', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $first = $rig->wg->addPeer('wg0');
    $conf = $rig->host->conf('wg0');
    $list = fn () => implode(' ', array_keys($rig->host->interfaces));

    // `wg show interfaces` fails once. Read as "nothing runs", the new peer would only be written
    // to the config, and dropped from it by the next change to the (running) link
    $rig->shell->on('sudo -n :helper interfaces', fn () => throw new CommandFailed('sudo: a password is required'));
    expect(fn () => $rig->wg->addPeer('wg0'))->toThrow(SystemException::class, 'a password is required')
        ->and(fn () => $rig->wg->listLinks())->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->getLink('wg0'))->toThrow(SystemException::class)
        ->and($rig->host->conf('wg0'))->toBe($conf);

    $rig->shell->on('sudo -n :helper interfaces', $list);
    $second = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $first->public_key, ['name' => 'first']);

    expect(array_keys($rig->host->confPeers('wg0')))->toBe([$first->public_key, $second->public_key]);
})->with('os');

it('does not read a config that cannot be read as a link that is not there', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, up: false);
    $rig->shell->on('sudo -n :helper conf-read :name', fn () => throw new CommandFailed('sudo: a password is required'));

    // Not a 404, not a backup without the link, not a clash check that skips it
    expect(fn () => $rig->wg->getLink('wg0'))->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->updateLink('wg0', ['port' => 51999]))->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->exportLinks())->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->createLink('wg2', '10.1.0.5/24', 51822))->toThrow(SystemException::class)
        // A name no link can have is still simply not there, without asking the host
        ->and($rig->wg->getLink('../etc/passwd'))->toBeNull()
        ->and($rig->wg->getPeerConfig('wg0', 'not-a-key'))->toBeNull()
        ->and($rig->wg->getPeerConfig('../etc', str_repeat('A', 43).'='))->toBeNull();
});

it('finds a client config by either form of the public key', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');

    expect($rig->wg->getPeerConfig('wg0', KeyManager::pubkeyToSafe($peer->public_key)))->toBe($peer->client_config)
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBe($peer->client_config);
});

// ─── Configs the app didn't write ───────────────────────────────────

it('shows a hand-written config but refuses to change it', function (string $os, Closure $change) {
    $rig = new Rig($os);
    $conf = $rig->host->confs['office'] = handWrittenConf();
    preg_match('/^PublicKey = (.+)$/m', $conf, $key);

    // Regenerating it would drop the routing table setting, the hook, the comment and the keepalive
    expect(fn () => $change($rig->wg, $key[1]))
        ->toThrow(ConflictException::class, "Link office has settings this app doesn't manage (Table, PostUp, comments, PersistentKeepalive), and a change made here would drop them.");

    $link = $rig->wg->getLink('office');
    expect($rig->host->conf('office'))->toBe($conf)
        ->and($rig->host->clients)->toBe([])
        ->and($link->address)->toBe('10.7.0.1/24')
        ->and($link->peers[0]->networks)->toBe('192.168.9.0/24')
        ->and($rig->wg->listLinks())->toBe(['office']);
})->with('os')->with([
    'a new peer' => [fn ($wg) => $wg->addPeer('office')],
    'a link setting' => [fn ($wg) => $wg->updateLink('office', ['dns' => '1.1.1.1'])],
    'starting it' => [fn ($wg) => $wg->updateLink('office', ['up' => true])],
    'a peer change' => [fn ($wg, string $key) => $wg->updatePeer('office', $key, ['name' => 'branch'])],
    'removing a peer' => [fn ($wg, string $key) => $wg->removePeer('office', $key)],
]);

it('refuses to change a running hand-written link before touching the interface', function () {
    $rig = new Rig('linux');
    $rig->host->confs['office'] = handWrittenConf();
    $rig->shell->run('sudo -n :helper up :name', ['name' => 'office']); // started by its owner
    $calls = count($rig->shell->calls);

    expect(fn () => $rig->wg->addPeer('office'))->toThrow(ConflictException::class);

    $after = array_column(array_slice($rig->shell->calls, $calls), 'command');
    expect($after)->not->toContain('sudo -n :helper peer-add :iface')->not->toContain('sudo -n :helper conf-write :name');
});

it('names what it would drop without quoting it', function () {
    $rig = new Rig('linux');
    // A second key line is one the app would lose: it must not end up in an error message
    $rig->host->confs['office'] = str_replace('Table = off', 'PrivateKey = '.($secret = (new KeyManager)->genkey()), handWrittenConf());

    try {
        $rig->wg->addPeer('office');
    } catch (ConflictException $e) {
    }

    expect($e->getMessage())->toContain('PrivateKey')->not->toContain($secret)->not->toContain('branch.example.com');
});

it('adopts a hand-written config that has nothing to lose, and can delete any', function (string $os) {
    $rig = new Rig($os);
    $keys = new KeyManager;
    // Only what the app writes too, typed a little differently
    $rig->host->confs['plain'] = "[Interface]\nAddress=10.8.0.1/24\nPrivateKey = {$keys->genkey()}\n  ListenPort =51901\n\n[Peer]\nPublicKey = {$keys->pubkey($keys->genkey())}\nAllowedIPs = 10.8.0.2/32\n";
    $rig->host->confs['office'] = handWrittenConf();

    $peer = $rig->wg->addPeer('plain', name: 'new');

    expect($peer->allowed_ips)->toBe('10.8.0.3/32')
        ->and($rig->host->conf('plain'))->toContain('# address = 10.8.0.1/24', 'ListenPort = 51901', '# name = new')
        ->and(array_values($rig->host->confPeers('plain')))->toBe(['10.8.0.2/32', '10.8.0.3/32']);

    $rig->wg->deleteLink('office');
    expect($rig->wg->listLinks())->toBe(['plain']);
})->with('os');

it('takes a config with hooks from another helper path or OS as its own', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, up: false);
    // As after moving the helper, or a config copied over from a Mac
    $rig->host->confs['wg0'] = preg_replace('/^(Post(?:Up|Down) = )\S+ (firewall-\w+) %i/m', '$1/opt/old/wgla-helper $2 %I', $rig->host->conf('wg0'));

    $rig->wg->addPeer('wg0');

    expect($rig->host->conf('wg0'))->toContain('PostUp = /usr/local/sbin/wgla-helper firewall-up %i %i')->not->toContain('/opt/old');
});

// ─── Settings as they are written ───────────────────────────────────

it('writes lists the way the helper takes them, however they were typed', function () {
    $rig = new Rig('linux');

    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, dns: '1.1.1.1 ,  8.8.8.8', allowed_ips: '10.0.0.0/8 ,192.168.0.0/16');
    $peer = $rig->wg->addPeer('wg0');

    expect($rig->host->conf('wg0'))->toContain("# dns = 1.1.1.1, 8.8.8.8\n", "# allowed_ips = 10.0.0.0/8, 192.168.0.0/16\n")
        ->and($peer->client_config)->toContain("DNS = 1.1.1.1, 8.8.8.8\n", "AllowedIPs = 10.0.0.0/8, 192.168.0.0/16\n");

    $rig->wg->updateLink('wg0', ['dns' => '9.9.9.9,1.1.1.1']);
    $rig->wg->updatePeer('wg0', $peer->public_key, ['allowed_ips' => '10.0.0.0/24 ,  10.1.0.0/24']);

    expect($rig->host->conf('wg0'))->toContain("# dns = 9.9.9.9, 1.1.1.1\n")
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain("DNS = 9.9.9.9, 1.1.1.1\n", "AllowedIPs = 10.0.0.0/24, 10.1.0.0/24\n");
});

it('refuses a link address that is no host in a subnet of its own', function (string $address, string $error) {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, up: false);

    expect(fn () => $rig->wg->createLink('wg0', $address, 51820))->toThrow(InvalidArgumentException::class, $error)
        ->and(fn () => $rig->wg->updateLink('wg1', ['address' => $address]))->toThrow(InvalidArgumentException::class, $error)
        ->and($rig->wg->listLinks())->toBe(['wg1']);
})->with([
    'every address' => ['10.0.0.1/0', 'covers every address'],
    'the network address' => ['10.0.0.0/24', 'network or broadcast address'],
    'the broadcast address' => ['10.0.0.255/24', 'network or broadcast address'],
]);

it('writes a mask as a plain number', function () {
    $rig = new Rig('linux');

    // "/08" is nothing `ip` or the helper's firewall arithmetic can read
    expect($rig->wg->createLink('wg0', '10.0.0.1/08', 51820)->address)->toBe('10.0.0.1/8')
        ->and($rig->host->conf('wg0'))->toContain("# address = 10.0.0.1/8\n", "Address = 10.0.0.1/8\n");
});

it('goes back to the default when a link\'s or peer\'s own client setting is taken out', function (string $os, mixed $nothing) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, dns: '9.9.9.9', keepalive: 15, allowed_ips: '10.0.0.0/24');
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => '1.1.1.1', 'allowed_ips' => '10.0.0.0/16']);

    // The link's own: back to the fixed defaults, for peers without their own
    $rig->wg->updateLink('wg0', ['dns' => $nothing, 'keepalive' => $nothing, 'allowed_ips' => $nothing]);

    expect(explode('[Interface]', $rig->host->conf('wg0'))[0])->not->toContain('# dns')->not->toContain('# keepalive')->not->toContain('# allowed_ips')
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("DNS = 8.8.8.8\n", 'PersistentKeepalive = 25', "AllowedIPs = 0.0.0.0/0\n")
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain("DNS = 1.1.1.1\n", 'PersistentKeepalive = 25', "AllowedIPs = 10.0.0.0/16\n");

    // The peer's own: back to the link's
    $rig->wg->updateLink('wg0', ['dns' => '9.9.9.9']);
    $updated = $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => $nothing, 'allowed_ips' => $nothing]);

    expect($updated->client_config)->toContain("DNS = 9.9.9.9\n", "AllowedIPs = 0.0.0.0/0\n");

    // A keepalive of 0 is a value (off), not "nothing"
    $rig->wg->updateLink('wg0', ['keepalive' => 0]);
    expect($rig->host->conf('wg0'))->toContain("# keepalive = 0\n")
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain('PersistentKeepalive = 0');
})->with('os')->with(['null' => [null], 'an empty value' => ['']]);

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
        ->and("{$rig->tmp}/locks/links.lock")->toBeFile('One lock for every change, whatever the link');
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

// ─── A peer's own client settings ───────────────────────────────────

it('stores a peer\'s own client settings with the peer, not in what its client config happens to say', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0', name: 'laptop');

    $updated = $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => '1.1.1.1 ,9.9.9.9', 'keepalive' => 5, 'allowed_ips' => '10.0.0.0/24']);

    expect($updated->clientSettings())->toBe(['dns' => '1.1.1.1, 9.9.9.9', 'keepalive' => 5, 'allowed_ips' => '10.0.0.0/24'])
        ->and($updated->toArray()['client'])->toBe($updated->clientSettings())
        ->and($updated->allowed_ips)->toBe('10.0.0.3/32', 'What the server routes to it is another matter')
        ->and($updated->client_config)->toContain("DNS = 1.1.1.1, 9.9.9.9\n", "AllowedIPs = 10.0.0.0/24\n", 'PersistentKeepalive = 5')
        ->and($rig->host->conf('wg0'))->toContain("[Peer]\n# name = laptop\n# dns = 1.1.1.1, 9.9.9.9\n# keepalive = 5\n# allowed_ips = 10.0.0.0/24\nPublicKey = {$custom->public_key}\n")
        ->and($rig->wg->getLink('wg0')->peers[0]->clientSettings())->toBe(['dns' => null, 'keepalive' => null, 'allowed_ips' => null])
        ->and($rig->wg->getLink('wg0')->peers[1]->clientSettings())->toBe($updated->clientSettings());

    // Through live changes, a restart, and being disabled
    $rig->wg->addPeer('wg0');
    $rig->wg->updateLink('wg0', ['port' => 51821, 'dns' => '8.8.4.4']);
    $rig->wg->updatePeer('wg0', $custom->public_key, ['enabled' => false]);

    expect($rig->host->conf('wg0'))->toContain("# [Peer] disabled\n# name = laptop\n# dns = 1.1.1.1, 9.9.9.9\n# keepalive = 5\n# allowed_ips = 10.0.0.0/24\n# PublicKey = {$custom->public_key}\n")
        ->and($rig->wg->getLink('wg0')->peers[1]->clientSettings())->toBe($updated->clientSettings())
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain("DNS = 1.1.1.1, 9.9.9.9\n", 'Endpoint = vpn.example.test:51821', 'PersistentKeepalive = 5')
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("DNS = 8.8.4.4\n", 'PersistentKeepalive = 25');

    // One taken out again: the others stay
    $rig->wg->updatePeer('wg0', $custom->public_key, ['keepalive' => null, 'enabled' => true]);
    expect($rig->wg->getLink('wg0')->peers[1]->clientSettings())->toBe(['dns' => '1.1.1.1, 9.9.9.9', 'keepalive' => null, 'allowed_ips' => '10.0.0.0/24'])
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain('PersistentKeepalive = 25');
})->with('os');

it('follows the link when a peer happens to have had the same value', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, dns: '9.9.9.9');
    $peer = $rig->wg->addPeer('wg0');

    // Nothing of its own: its config said 9.9.9.9 because its link did. Compared, as it once
    // was, a client config kept whatever differed from the default of the moment.
    $rig->wg->updateLink('wg0', ['dns' => '1.1.1.1']);
    $rig->wg->updateLink('wg0', ['dns' => null]);

    expect($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain("DNS = 8.8.8.8\n")
        ->and($rig->host->conf('wg0'))->not->toContain('# dns');
});

it('records once what the peers of an older config had of their own', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, dns: '9.9.9.9', up: $up);
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => '1.1.1.1', 'allowed_ips' => '10.0.0.0/24']);
    // As an older version left it: the peer's own values only in its client config, stored whole
    $rig->host->confs['wg0'] = asFormat1($rig->host->conf('wg0'), $rig->host, 'wg0', [
        $plain->public_key => $rig->wg->getPeerConfig('wg0', $plain->public_key),
        $custom->public_key => $rig->wg->getPeerConfig('wg0', $custom->public_key),
    ]);
    expect($rig->host->conf('wg0'))->not->toContain('# format')->not->toContain('1.1.1.1');

    // Readable as it is, and the first change brings it up to date
    expect($rig->wg->getLink('wg0')->peers[1]->clientSettings())->toBe(['dns' => null, 'keepalive' => null, 'allowed_ips' => null]);
    $rig->wg->updateLink('wg0', ['dns' => '8.8.4.4']);

    expect($rig->host->conf('wg0'))->toContain("# format = 2\n", "# dns = 1.1.1.1\n# allowed_ips = 10.0.0.0/24\nPublicKey = {$custom->public_key}\n")
        ->and($rig->wg->getLink('wg0')->peers[0]->clientSettings())->toBe(['dns' => null, 'keepalive' => null, 'allowed_ips' => null])
        ->and($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("DNS = 8.8.4.4\n")
        ->and($rig->wg->getPeerConfig('wg0', $custom->public_key))->toContain("DNS = 1.1.1.1\n", "AllowedIPs = 10.0.0.0/24\n");

    // Nothing is read out of a stored file again but the key: not even one edited by hand
    $safe = KeyManager::pubkeyToSafe($plain->public_key);
    $rig->host->clients["wg0/{$safe}"] = str_replace('DNS = 9.9.9.9', 'DNS = 4.4.4.4', $rig->host->clients["wg0/{$safe}"]);
    $rig->wg->updateLink('wg0', ['keepalive' => 30]);

    expect($rig->wg->getPeerConfig('wg0', $plain->public_key))->toContain("DNS = 8.8.4.4\n")
        ->and($rig->wg->getLink('wg0')->peers[0]->dns)->toBeNull();
})->with('os')->with(['running' => true, 'stopped' => false]);

// ─── Moving a link, and other leftovers ─────────────────────────────

it('moves a link to another subnet with its peers, when told to', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, address6: 'fd12::1/64', up: $up);
    $first = $rig->wg->addPeer('wg0');
    $branch = $rig->wg->addPeer('wg0', '10.0.0.77', networks: '192.168.1.0/24');
    $rig->wg->updatePeer('wg0', $first->public_key, ['enabled' => false]);

    // Not by itself: every client would need a new config
    expect(fn () => $rig->wg->updateLink('wg0', ['address' => '10.1.0.1/24']))
        ->toThrow(InvalidArgumentException::class, 'Peer 10.0.0.2 would not fit the new address 10.1.0.1/24. To move the link\'s peers along (each keeps its host number, and every client needs its new config), pass move_peers (--move-peers).');

    $link = $rig->wg->updateLink('wg0', ['address' => '10.1.0.1/24', 'move_peers' => true]);

    expect($link->address)->toBe('10.1.0.1/24')
        ->and($link->up)->toBe($up)
        ->and(array_map(fn (PeerInfo $p) => $p->allowed_ips, $link->peers))->toBe(['10.1.0.2/32, fd12::2/128', '10.1.0.77/32, fd12::4d/128, 192.168.1.0/24'])
        ->and($link->peers[0]->enabled)->toBeFalse()
        ->and($rig->wg->getPeerConfig('wg0', $first->public_key))->toContain("Address = 10.1.0.2/32, fd12::2/128\n")
        ->and($rig->wg->getPeerConfig('wg0', $branch->public_key))->toContain("Address = 10.1.0.77/32, fd12::4d/128\n");
    if ($up) {
        expect($rig->host->runtimePeers('wg0'))->toBe([$branch->public_key => '10.1.0.77/32, fd12::4d/128, 192.168.1.0/24']);
    }

    // The next free address is in the new subnet
    expect($rig->wg->addPeer('wg0')->allowed_ips)->toBe('10.1.0.3/32, fd12::3/128');
})->with('os')->with(['running' => true, 'stopped' => false]);

it('refuses to move peers where they have no place', function (string $address, string $error) {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->addPeer('wg0', '10.0.0.5');
    $rig->wg->addPeer('wg0', '10.0.0.200');
    $conf = $rig->host->conf('wg0');

    expect(fn () => $rig->wg->updateLink('wg0', ['address' => $address, 'move_peers' => true]))->toThrow(InvalidArgumentException::class, $error)
        ->and($rig->host->conf('wg0'))->toBe($conf);
})->with([
    'a subnet too small for a host number' => ['10.1.0.1/25', "Peer 10.0.0.200 can't move along: its host number 200 doesn't fit 10.1.0.1/25."],
    "the link's own new address" => ['10.1.0.5/24', "Peer 10.1.0.5 would not fit the new address 10.1.0.5/24: that is the link's own"],
]);

it('leaves peers where they are when a link only grows or shrinks around them', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0', '10.0.0.127');

    expect($rig->wg->updateLink('wg0', ['address' => '10.0.0.1/16'])->peers[0]->allowed_ips)->toBe('10.0.0.127/32')
        // .127 would be the broadcast address of a /25
        ->and(fn () => $rig->wg->updateLink('wg0', ['address' => '10.0.0.1/25']))->toThrow(InvalidArgumentException::class, 'the network or the broadcast address')
        ->and($rig->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.127/32']);
});

it('keeps the link\'s mask when a new address comes without one', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/16', 51820);
    $rig->wg->addPeer('wg0', '10.0.200.7');

    // It used to become a /24, whatever the link was
    expect($rig->wg->updateLink('wg0', ['address' => '10.0.0.9'])->address)->toBe('10.0.0.9/16')
        ->and($rig->wg->createLink('wg1', '10.1.0.1', 51821)->address)->toBe('10.1.0.1/24', 'A new link without one is a /24');
});

it('restarts the link when a peer with networks behind it goes, so its routes go too', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $plain = $rig->wg->addPeer('wg0');
    $branch = $rig->wg->addPeer('wg0', networks: '192.168.1.0/24');
    $starts = fn () => count($rig->shell->callsTo('sudo -n :helper up :name'));
    $before = $starts();

    $rig->wg->removePeer('wg0', $branch->public_key);

    expect($starts())->toBe($before + 1, 'wg-quick only takes routes away when the link stops')
        ->and($rig->host->runtimePeers('wg0'))->toBe([$plain->public_key => '10.0.0.2/32'])
        ->and($rig->wg->getPeerConfig('wg0', $branch->public_key))->toBeNull();

    // A peer without networks goes live, as before
    $rig->wg->removePeer('wg0', $plain->public_key);
    expect($starts())->toBe($before + 1)->and($rig->host->runtimePeers('wg0'))->toBe([]);
})->with('os');

it('keeps a peer whose removal the link does not restart with', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $branch = $rig->wg->addPeer('wg0', networks: '192.168.1.0/24');
    $rig->host->failNextStart = true;

    expect(fn () => $rig->wg->removePeer('wg0', $branch->public_key))->toThrow(SystemException::class, 'was undone');

    expect($rig->host->runtimePeers('wg0'))->toBe([$branch->public_key => '10.0.0.2/32, 192.168.1.0/24'])
        ->and($rig->wg->getPeerConfig('wg0', $branch->public_key))->toBe($branch->client_config);
});

it('leaves a disabled peer where it was among the others', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: $up);
    $keys = array_map(fn (string $name) => $rig->wg->addPeer('wg0', name: $name)->public_key, ['a', 'b', 'c']);
    $order = fn () => implode('', array_map(fn (PeerInfo $p) => $p->name, $rig->wg->getLink('wg0')->peers));

    $rig->wg->updatePeer('wg0', $keys[0], ['enabled' => false]);
    $rig->wg->updatePeer('wg0', $keys[1], ['enabled' => false]);
    expect($order())->toBe('abc');

    $rig->wg->updatePeer('wg0', $keys[0], ['enabled' => true]);
    $rig->wg->addPeer('wg0', name: 'd');
    expect($order())->toBe('abcd');
})->with('os')->with(['running' => true, 'stopped' => false]);

// ─── Client configs, built when asked for ───────────────────────────

it('stores only a peer\'s private key and builds its client config when asked', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $writes = fn () => count($rig->shell->callsTo('sudo -n :helper client-write :link :key'));

    expect(array_values($rig->host->clients))->toHaveCount(1)
        ->and(array_values($rig->host->clients)[0])->toContain("PrivateKey = {$peer->private_key}")->not->toContain('Endpoint')->not->toContain('[Peer]')
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBe($peer->client_config);

    // A link change writes no file per peer: the next read simply has it
    $before = $writes();
    $rig->wg->updateLink('wg0', ['port' => 51821, 'dns' => '1.1.1.1', 'address6' => 'fd12::1/64']);

    expect($writes())->toBe($before)
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))
        ->toContain("PrivateKey = {$peer->private_key}\n", "Address = 10.0.0.2/32, fd12::2/128\n", "DNS = 1.1.1.1\n", 'Endpoint = vpn.example.test:51821');
})->with('os');

it('builds a client config for what this server is called now', function () {
    $rig = new Rig('linux'); // vpn.example.test
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');

    // The same host after WIREGUARD_HOSTNAME changed: nothing was stored that could be stale
    $config = array_merge(require dirname(__DIR__, 2).'/config/wireguard.php', ['hostname' => 'new.example.test']);
    $driver = new LinuxDriver($rig->shell, $config['helper']);
    $renamed = new WireGuard($config, $driver, new WireGuardValidator, new KeyManager, new ConfigBuilder($config, $driver), new IpAllocator, "{$rig->tmp}/locks");

    expect($renamed->getPeerConfig('wg0', $peer->public_key))->toContain('Endpoint = new.example.test:51820', "PrivateKey = {$peer->private_key}\n");
});

it('changes and shows a peer whose private key is not stored here', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $rig->host->clients = []; // as for a peer that was added by hand

    $updated = $rig->wg->updatePeer('wg0', $peer->public_key, ['name' => 'someone', 'enabled' => false]);

    expect($updated)->name->toBe('someone')->enabled->toBeFalse()->client_config->toBeNull()
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toBeNull('There is no config without its key')
        ->and($rig->wg->getPeer('wg0', KeyManager::pubkeyToSafe($peer->public_key))->name)->toBe('someone')
        ->and($rig->wg->getPeer('wg0', 'not-a-key'))->toBeNull()
        ->and($rig->wg->getPeer('nope', $peer->public_key))->toBeNull();
});

it('leaves a config out of a client config when a peer has no preshared key', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: false);
    $peer = $rig->wg->addPeer('wg0');
    $rig->host->confs['wg0'] = preg_replace('/^PresharedKey = .*\n/m', '', $rig->host->conf('wg0'));

    expect($rig->wg->getPeerConfig('wg0', $peer->public_key))->not->toContain('PresharedKey')->toContain("[Peer]\nPublicKey = ", "AllowedIPs = 0.0.0.0/0\n");
});

// ─── A link's MTU, and its own settings read back ───────────────────

it('gives a link an MTU, for its interface and its clients', function (string $os) {
    $rig = new Rig($os);
    $starts = fn () => count($rig->shell->callsTo('sudo -n :helper up :name'));

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, dns: '9.9.9.9', keepalive: 15, mtu: 1380);
    $peer = $rig->wg->addPeer('wg0');

    expect($link->toArray())->toMatchArray(['mtu' => 1380, 'client' => ['dns' => '9.9.9.9', 'keepalive' => 15, 'allowed_ips' => null]])
        ->and($rig->host->conf('wg0'))->toContain("ListenPort = 51820\nMTU = 1380\n")
        ->and($peer->client_config)->toContain("Address = 10.0.0.2/32\nDNS = 9.9.9.9\nMTU = 1380\n");

    // wg-quick sets it when the link starts: a change restarts a running link, the same value doesn't
    $before = $starts();
    $rig->wg->updateLink('wg0', ['mtu' => 1380, 'keepalive' => 20]);
    expect($starts())->toBe($before);
    expect($rig->wg->updateLink('wg0', ['mtu' => 1400])->mtu)->toBe(1400)
        ->and($starts())->toBe($before + 1)
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->toContain("MTU = 1400\n");

    // Taken out again: wg-quick's own, and no MTU line for clients
    expect($rig->wg->updateLink('wg0', ['mtu' => null])->mtu)->toBeNull()
        ->and($rig->host->conf('wg0'))->not->toContain('MTU')
        ->and($rig->wg->getPeerConfig('wg0', $peer->public_key))->not->toContain('MTU')
        ->and($rig->wg->getLink('wg0')->toArray()['client'])->toBe(['dns' => '9.9.9.9', 'keepalive' => 20, 'allowed_ips' => null]);
})->with('os');

it('refuses an MTU the link could not use', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, mtu: 1000);

    expect(fn () => $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, mtu: 100))->toThrow(InvalidArgumentException::class, 'Invalid MTU: 100')
        ->and(fn () => $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, address6: 'fd12::1/64', mtu: 1000))->toThrow(InvalidArgumentException::class, 'as the link has an IPv6 address')
        // IPv6 needs 1280: not on a link that has a smaller one either
        ->and(fn () => $rig->wg->updateLink('wg0', ['address6' => 'fd12::1/64']))->toThrow(InvalidArgumentException::class, 'Invalid MTU: 1000')
        ->and($rig->wg->updateLink('wg0', ['address6' => 'fd12::1/64', 'mtu' => 1280])->mtu)->toBe(1280);
});

// ─── A peer the server connects to ──────────────────────────────────

it('connects to a peer itself when the peer has a remote', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: $up);
    $added = fn () => array_column($rig->shell->callsTo('sudo -n :helper peer-add :iface'), 'input');
    $removed = fn () => count($rig->shell->callsTo('sudo -n :helper peer-remove :iface :pubkey'));

    $branch = $rig->wg->addPeer('wg0', name: 'branch', remote: ' branch.example.com:51820 ');

    // The server dials, and keeps the path open: a keepalive of its own
    expect($branch->remote)->toBe('branch.example.com:51820')
        ->and($branch->toArray()['remote'])->toBe('branch.example.com:51820')
        ->and($rig->host->conf('wg0'))->toContain("AllowedIPs = 10.0.0.2/32\nEndpoint = branch.example.com:51820\nPersistentKeepalive = 25")
        ->and($branch->client_config)->not->toContain('branch.example.com', 'Its client config is as any other');
    if ($up) {
        expect($added()[0])->toContain("AllowedIPs = 10.0.0.2/32\nEndpoint = branch.example.com:51820\nPersistentKeepalive = 25\n");
    }

    // Somewhere else: `wg` can't take an endpoint away again, so the peer is put on the interface anew
    $before = $removed();
    $moved = $rig->wg->updatePeer('wg0', $branch->public_key, ['remote' => '[2001:DB8::7]:51821']);
    expect($moved->remote)->toBe('[2001:db8::7]:51821')
        ->and($rig->wg->getLink('wg0')->peers[0]->remote)->toBe('[2001:db8::7]:51821');
    if ($up) {
        expect($removed())->toBe($before + 1)->and(array_last($added()))->toContain("Endpoint = [2001:db8::7]:51821\n")
            ->and($rig->host->runtimePeers('wg0'))->toHaveKey($branch->public_key);
    }

    // Kept while disabled and through a restart; gone when taken out
    $rig->wg->updatePeer('wg0', $branch->public_key, ['enabled' => false]);
    $rig->wg->updateLink('wg0', ['port' => 51821]);
    expect($rig->host->conf('wg0'))->toContain("# AllowedIPs = 10.0.0.2/32\n# Endpoint = [2001:db8::7]:51821\n# PersistentKeepalive = 25");

    $rig->wg->updatePeer('wg0', $branch->public_key, ['enabled' => true, 'remote' => null]);
    expect($rig->host->conf('wg0'))->not->toContain('Endpoint')->not->toContain('PersistentKeepalive')
        ->and($rig->wg->getLink('wg0')->peers[0])->remote->toBeNull()->enabled->toBeTrue();
})->with('os')->with(['running' => true, 'stopped' => false]);

it('manages a hand-written site-to-site config: an MTU, and a peer it connects to', function () {
    $rig = new Rig('linux');
    $keys = new KeyManager;
    $rig->host->confs['site'] = "[Interface]\nAddress = 10.8.0.1/24\nPrivateKey = {$keys->genkey()}\nListenPort = 51901\nMTU = 1380\n\n"
        ."[Peer]\nPublicKey = {$keys->pubkey($keys->genkey())}\nAllowedIPs = 10.8.0.2/32, 192.168.9.0/24\nEndpoint = branch.example.com:51820\nPersistentKeepalive = 25\n";

    $rig->wg->addPeer('site');

    $link = $rig->wg->getLink('site');
    expect($link->mtu)->toBe(1380)
        ->and($link->peers[0])->remote->toBe('branch.example.com:51820')->networks->toBe('192.168.9.0/24')
        ->and($rig->host->conf('site'))->toContain("MTU = 1380\n", "Endpoint = branch.example.com:51820\nPersistentKeepalive = 25\n");
});

// ─── New keys for a peer ────────────────────────────────────────────

it('gives a peer new keys and keeps everything else about it', function (string $os, bool $up) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, up: $up);
    $first = $rig->wg->addPeer('wg0');
    $laptop = $rig->wg->addPeer('wg0', name: 'laptop', remote: 'laptop.example.com:51820');
    $rig->wg->updatePeer('wg0', $laptop->public_key, ['dns' => '1.1.1.1']);
    $last = $rig->wg->addPeer('wg0');

    $new = $rig->wg->rekeyPeer('wg0', $laptop->public_key);

    expect($new->public_key)->not->toBe($laptop->public_key)
        ->and($new->private_key)->not->toBeNull()->not->toBe($laptop->private_key)
        ->and($new->preshared_key)->not->toBe($laptop->preshared_key)
        ->and($new)->name->toBe('laptop')->dns->toBe('1.1.1.1')->allowed_ips->toBe('10.0.0.3/32')->remote->toBe('laptop.example.com:51820')
        ->and($new->client_config)->toContain("PrivateKey = {$new->private_key}\n", "PresharedKey = {$new->preshared_key}\n", "Address = 10.0.0.3/32\n", "DNS = 1.1.1.1\n")
        // In its place, under its new key; the old one is gone everywhere
        ->and(array_map(fn (PeerInfo $p) => $p->public_key, $rig->wg->getLink('wg0')->peers))->toBe([$first->public_key, $new->public_key, $last->public_key])
        ->and($rig->host->conf('wg0'))->not->toContain($laptop->public_key)->not->toContain($laptop->preshared_key)
        ->and($rig->wg->getPeerConfig('wg0', $laptop->public_key))->toBeNull()
        ->and($rig->wg->getPeerConfig('wg0', $new->public_key))->toBe($new->client_config)
        ->and($rig->host->clients)->toHaveCount(3);
    if ($up) {
        expect($rig->host->runtimePeers('wg0'))->toHaveKey($new->public_key, '10.0.0.3/32')->not->toHaveKey($laptop->public_key)
            ->and($rig->wg->getLink('wg0')->peers[1]->transfer_rx)->toBe(0);
    }

    // A disabled peer too, without ever touching the interface
    $rig->wg->updatePeer('wg0', $new->public_key, ['enabled' => false]);
    $again = $rig->wg->rekeyPeer('wg0', $new->public_key);

    expect($again->enabled)->toBeFalse()
        ->and($rig->host->conf('wg0'))->toContain("# PublicKey = {$again->public_key}\n")
        ->and(fn () => $rig->wg->rekeyPeer('wg0', $laptop->public_key))->toThrow(NotFoundException::class);
    if ($up) {
        expect($rig->host->runtimePeers('wg0'))->not->toHaveKey($again->public_key);
    }
})->with('os')->with(['running' => true, 'stopped' => false]);

// ─── Firewall rules that went missing; the server's own addresses ───

it('notices when a running link lost its firewall rules, and puts them back', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true);
    expect($rig->wg->getLink('wg0')->firewall)->toBe('ok');

    unset($rig->host->firewall['wg0']); // e.g. `nft -f /etc/nftables.conf`, which starts with "flush ruleset"

    expect($rig->wg->getLink('wg0')->toArray()['firewall'])->toBe('missing')
        ->and($rig->wg->repairLink('wg0')->firewall)->toBe('ok')
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true]);

    // Nothing to say, and nothing to repair, for a link without rules or one that is down
    expect($rig->wg->updateLink('wg0', ['forward' => false, 'nat' => false])->firewall)->toBeNull()
        ->and($rig->wg->repairLink('wg0')->firewall)->toBeNull()
        ->and($rig->wg->createLink('wg1', '10.1.0.1/24', 51821, forward: true, up: false)->firewall)->toBeNull()
        ->and($rig->wg->repairLink('wg1')->up)->toBeFalse()
        ->and($rig->host->firewall)->toBe([])
        ->and(fn () => $rig->wg->repairLink('nope'))->toThrow(NotFoundException::class);
})->with('os');

it('refuses to route an address the server needs itself to a peer', function (string $os, string $network, string $address) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    // It would send that traffic into the tunnel, and cut the server off from its own network
    expect(fn () => $rig->wg->addPeer('wg0', networks: $network))
        ->toThrow(InvalidArgumentException::class, "{$network} covers {$address}, an address this server uses itself")
        ->and($rig->host->confPeers('wg0'))->toBe([]);
})->with('os')->with([
    'its address on the LAN' => ['192.0.2.0/28', '192.0.2.10'],
    'its default gateway' => ['192.0.2.1/32', '192.0.2.1'],
    'its IPv6 address' => ['2001:db8:f::/64', '2001:db8:f::10'],
]);

it('routes a network next to the server\'s own to a peer all the same', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);

    // The other half of the server's /24: neither its address nor its gateway is in it
    expect($rig->wg->addPeer('wg0', networks: '192.0.2.128/25')->networks)->toBe('192.0.2.128/25');
});
