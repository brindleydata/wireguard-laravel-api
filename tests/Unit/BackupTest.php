<?php

use App\DTOs\PeerInfo;
use App\Exceptions\ConflictException;
use App\Exceptions\SystemException;
use App\Services\KeyManager;
use Tests\Fakes\CommandFailed;
use Tests\Support\Rig;

/*
 * Backups between simulated servers (Tests\Fakes\FakeHost), including moves to another
 * hostname and to the other OS.
 */

const BACKUP_PASSPHRASE = 'correct horse battery staple';

afterEach(fn () => Rig::cleanup());

/**
 * A server with wg0 running (forward + NAT, two peers, one with its own DNS) and wg1 stopped.
 *
 * @return array{0: Rig, 1: array<string, PeerInfo>}
 */
function backedUpServer(string $os): array
{
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true);
    $plain = $rig->wg->addPeer('wg0');
    $custom = $rig->wg->addPeer('wg0');
    $rig->wg->updatePeer('wg0', $custom->public_key, ['dns' => '9.9.9.9']);
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, up: false);
    $stopped = $rig->wg->addPeer('wg1');

    return [$rig, compact('plain', 'custom', 'stopped')];
}

// ─── Encryption ─────────────────────────────────────────────────────

it('encrypts a backup so only the passphrase opens it', function () {
    [$rig] = backedUpServer('linux');
    $payload = $rig->backup->create();
    $file = $rig->backup->encrypt($payload, BACKUP_PASSPHRASE);

    expect($file)->not->toContain('PrivateKey')
        ->and(json_decode($file, true))->toMatchArray(['format' => 'wgla-backup', 'version' => 1])
        ->and($rig->backup->decrypt($file, BACKUP_PASSPHRASE))->toBe($payload)
        ->and(fn () => $rig->backup->decrypt($file, 'not the passphrase'))->toThrow(InvalidArgumentException::class, 'Wrong passphrase');
});

it('rejects a damaged, foreign or crafted file', function (Closure $tamper, string $error) {
    [$rig] = backedUpServer('linux');
    $file = json_decode($rig->backup->encrypt($rig->backup->create(), BACKUP_PASSPHRASE), true);

    expect(fn () => $rig->backup->decrypt(json_encode($tamper($file)), BACKUP_PASSPHRASE))->toThrow(InvalidArgumentException::class, $error);
})->with([
    'a changed byte' => [fn ($f) => [...$f, 'ciphertext' => base64_encode(substr_replace(base64_decode($f['ciphertext']), 'X', 40, 1))], 'Wrong passphrase, or the backup file is damaged'],
    'not a backup' => [fn ($f) => ['hello' => 'world'], 'Not a WireGuard API backup file'],
    'absurd key-derivation memory' => [fn ($f) => [...$f, 'kdf' => [...$f['kdf'], 'mem' => PHP_INT_MAX]], 'unsupported encryption settings'],
]);

it('wants a passphrase of at least 12 characters', function () {
    [$rig] = backedUpServer('linux');

    expect(fn () => $rig->backup->encrypt($rig->backup->create(), 'short'))->toThrow(InvalidArgumentException::class, 'at least 12');
});

// ─── Restore ────────────────────────────────────────────────────────

it('restores every link on another server, re-rendered for it', function (string $from, string $to) {
    [$old, $peers] = backedUpServer($from);
    $payload = $old->backup->decrypt($old->backup->encrypt($old->backup->create(), BACKUP_PASSPHRASE), BACKUP_PASSPHRASE);
    $new = new Rig($to, hostname: 'new.example.test');

    $report = $new->backup->restore($payload, ['wg0' => 'restore', 'wg1' => 'restore']);

    $wg0 = $new->wg->getLink('wg0');
    expect($report)->toMatchArray(['restored' => ['wg0', 'wg1'], 'skipped' => [], 'clients' => 3, 'hostname' => 'new.example.test', 'hostname_changed' => true])
        // Same keys and peers, same running state
        ->and($wg0->public_key)->toBe($old->wg->getLink('wg0')->public_key)
        ->and($wg0->up)->toBeTrue()
        ->and($new->host->runtimePeers('wg0'))->toBe($old->host->runtimePeers('wg0'))
        ->and($new->wg->getLink('wg1')->up)->toBeFalse()
        ->and($new->host->confPeers('wg1'))->toBe([$peers['stopped']->public_key => '10.1.0.2/32'])
        // The config was rebuilt for this OS: its hooks
        ->and($new->host->conf('wg0'))->toContain($to === 'mac' ? 'firewall-up %I %i' : 'firewall-up %i %i')
        ->and($new->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true]);

    // Client configs: same keys, this server as Endpoint, per-peer overrides kept
    $plain = $new->wg->getPeerConfig('wg0', $peers['plain']->public_key);
    $custom = $new->wg->getPeerConfig('wg0', $peers['custom']->public_key);
    expect($plain)->toContain('Endpoint = new.example.test:51820', 'PrivateKey = '.$peers['plain']->private_key, 'DNS = 8.8.8.8')
        ->and($custom)->toContain('Endpoint = new.example.test:51820', 'DNS = 9.9.9.9');
})->with([
    'Linux to Linux' => ['linux', 'linux'],
    'macOS to Linux' => ['mac', 'linux'],
    'Linux to macOS' => ['linux', 'mac'],
]);

it('restores a dual-stack link with its IPv6 prefix and peer addresses', function (string $to) {
    $old = new Rig('linux');
    $old->wg->createLink('wg0', '10.0.0.1/24', 51820, nat: true, address6: 'fd12::1/64');
    $peer = $old->wg->addPeer('wg0');
    $payload = $old->backup->create();
    $new = new Rig($to, hostname: 'new.example.test');

    $new->backup->restore($payload, ['wg0' => 'restore']);

    expect($new->wg->getLink('wg0')->address6)->toBe('fd12::1/64')
        ->and($new->host->confPeers('wg0'))->toBe([$peer->public_key => '10.0.0.2/32, fd12::2/128'])
        ->and($new->host->firewall['wg0']['nat6'])->toBe('fd12::1/64')
        ->and($new->wg->getPeerConfig('wg0', $peer->public_key))->toContain('Address = 10.0.0.2/32, fd12::2/128', 'AllowedIPs = 0.0.0.0/0, ::/0');

    // A server whose link already uses an overlapping prefix can't take it
    $taken = new Rig($to);
    $taken->wg->createLink('wg5', '10.5.0.1/24', 51825, address6: 'fd12::5/64');
    expect($taken->backup->problems($payload, 'wg0'))->toBe(['Prefix fd12::1/64 overlaps link wg5 (fd12::5/64)']);
})->with(['Linux' => 'linux', 'macOS' => 'mac']);

it('restores peer names, disabled peers and networks behind peers', function (string $to) {
    $old = new Rig('linux');
    $old->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true);
    $branch = $old->wg->addPeer('wg0', name: 'branch', networks: '192.168.1.0/24');
    $laptop = $old->wg->addPeer('wg0', name: 'laptop');
    $old->wg->updatePeer('wg0', $laptop->public_key, ['enabled' => false]);
    $new = new Rig($to, hostname: 'new.example.test');

    $new->backup->restore($old->backup->create(), ['wg0' => 'restore']);

    $peers = $new->wg->getLink('wg0')->peers;
    expect(array_map(fn (PeerInfo $p) => [$p->name, $p->enabled, $p->networks], $peers))->toBe([
        ['branch', true, '192.168.1.0/24'],
        ['laptop', false, null],
    ])
        ->and($new->host->runtimePeers('wg0'))->toBe([$branch->public_key => '10.0.0.2/32, 192.168.1.0/24'])
        ->and($new->wg->getPeerConfig('wg0', $laptop->public_key))->toContain('Endpoint = new.example.test:51820');
})->with(['Linux' => 'linux', 'macOS' => 'mac']);

it("falls back to this server's outbound interface when the old one doesn't exist here", function () {
    [$old] = backedUpServer('mac'); // NAT out of en0
    $new = new Rig('linux');

    $report = $new->backup->restore($old->backup->create(), ['wg0' => 'restore', 'wg1' => 'restore']);

    expect($report['ifout']['wg0'])->toBe(['en0', 'eth0'])
        ->and($new->wg->getLink('wg0')->ifout)->toBe('eth0');
});

it('keeps or replaces a link that already exists, as chosen', function (string $choice) {
    [$old] = backedUpServer('linux');
    $payload = $old->backup->create();
    $new = new Rig('linux');
    $mine = $new->wg->createLink('wg0', '10.0.0.1/24', 51820);

    $report = $new->backup->restore($payload, ['wg0' => $choice, 'wg1' => 'restore']);

    expect($new->wg->getLink('wg0')->public_key)->toBe($choice === 'replace' ? $old->wg->getLink('wg0')->public_key : $mine->public_key)
        ->and($report['restored'])->toBe($choice === 'replace' ? ['wg0', 'wg1'] : ['wg1'])
        ->and($report['skipped'])->toBe($choice === 'replace' ? [] : ['wg0']);
})->with(['skip', 'replace']);

it('finds clashes with links that stay, not with ones being replaced', function () {
    [$old] = backedUpServer('linux');
    $payload = $old->backup->create();
    $new = new Rig('linux');
    $new->wg->createLink('wg9', '10.0.0.200/24', 51820); // same port and subnet as the backed-up wg0

    expect($new->backup->problems($payload, 'wg0'))->toBe(['Port 51820 is already used by link wg9', 'Subnet 10.0.0.1/24 overlaps link wg9 (10.0.0.200/24)'])
        ->and($new->backup->problems($payload, 'wg0', ignore: ['wg9']))->toBe([])
        ->and($new->backup->problems($payload, 'wg1'))->toBe([])
        ->and(fn () => $new->backup->restore($payload, ['wg0' => 'restore']))->toThrow(ConflictException::class, 'Port 51820 is already used by link wg9');
});

it('finds what the restore itself would refuse, networks behind peers included', function () {
    $old = new Rig('linux');
    $old->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $old->wg->addPeer('wg0', networks: '192.168.50.0/24');
    $payload = $old->backup->create();

    // A link here whose peer routes the backed-up link's subnet
    $routed = new Rig('linux');
    $routed->wg->createLink('wgx', '10.5.0.1/24', 51821);
    $routed->wg->addPeer('wgx', networks: '10.0.0.0/16');
    expect($routed->backup->problems($payload, 'wg0'))->toBe(['10.0.0.1/24 overlaps 10.0.0.0/16, routed to a peer of link wgx']);

    // A link here in the subnet that a backed-up peer routes
    $lan = new Rig('linux');
    $lan->wg->createLink('wgy', '192.168.50.1/24', 51822);
    expect($lan->backup->problems($payload, 'wg0'))->toBe(['192.168.50.0/24 overlaps 192.168.50.1/24 of link wgy'])
        ->and(fn () => $lan->backup->restore($payload, ['wg0' => 'restore']))->toThrow(ConflictException::class, 'of link wgy');

    // A name another network interface has, and a config that isn't valid
    $payload['links']['eth0'] = $payload['links']['wg0'];
    $payload['links']['bad'] = ['conf' => str_replace('ListenPort = 51820', 'ListenPort = 0', $payload['links']['wg0']['conf']), 'clients' => [], 'up' => false];
    $empty = new Rig('linux');
    expect($empty->backup->problems($payload, 'eth0'))->toBe(['A network interface named eth0 already exists'])
        ->and($empty->backup->problems($payload, 'bad'))->toBe(['Invalid port number: 0'])
        ->and($empty->backup->problems($payload, 'wg0'))->toBe([]);
});

it('does not restore over a WireGuard interface that runs without a config', function () {
    [$old] = backedUpServer('linux');
    $payload = $old->backup->create();
    $new = new Rig('linux');
    // Something else started it: replacing it would mean stopping what this app doesn't manage
    $new->host->addUnmanagedInterface('wg0');
    $before = $new->host->interfaces;

    expect($new->backup->problems($payload, 'wg0', ignore: ['wg0']))
        ->toBe(['wg0 is a running WireGuard interface without a config here: this app can show it, but not change, stop or delete it. Manage it where it was started.'])
        ->and(fn () => $new->backup->restore($payload, ['wg0' => 'replace']))->toThrow(ConflictException::class, 'without a config here')
        ->and($new->host->interfaces)->toBe($before)
        ->and($new->host->files())->toBe([]);
});

it('leaves a link alone when the one to replace it with cannot be restored', function (Closure $obstacle, string $exception) {
    [$old] = backedUpServer('linux');
    $payload = $old->backup->create();
    $new = new Rig('linux');
    $mine = $new->wg->createLink('wg0', '10.9.0.1/24', 51820, forward: true);
    $peer = $new->wg->addPeer('wg0');
    $obstacle($new);

    expect(fn () => $new->backup->restore($payload, ['wg0' => 'replace']))->toThrow($exception);

    expect($new->wg->getLink('wg0'))->public_key->toBe($mine->public_key)->up->toBeTrue()
        ->and($new->host->runtimePeers('wg0'))->toBe([$peer->public_key => '10.9.0.2/32'])
        ->and($new->wg->getPeerConfig('wg0', $peer->public_key))->toBe($peer->client_config)
        ->and($new->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => false]);
})->with([
    'a clash with another link' => [function (Rig $rig) {
        $rig->wg->createLink('wgx', '10.5.0.1/24', 51821);
        $rig->wg->addPeer('wgx', networks: '10.0.0.0/16'); // the backed-up wg0 is 10.0.0.1/24
    }, ConflictException::class],
    'a config the helper refuses' => [function (Rig $rig) {
        $rig->shell->on('sudo -n :helper conf-write :name', fn () => throw new CommandFailed('wgla-helper: not allowed in a link config'));
    }, SystemException::class],
]);

it('keeps a restored link that does not start, stopped', function (string $os, bool $replace) {
    [$old, $peers] = backedUpServer($os);
    $payload = $old->backup->create();
    $new = new Rig($os, hostname: 'new.example.test');
    if ($replace) {
        $new->wg->createLink('wg0', '10.9.0.1/24', 51820);
        $new->wg->addPeer('wg0');
    }
    // The restored link's own start, not the stop of the one it replaces
    $new->host->failNextStart = true;

    $report = $new->backup->restore($payload, ['wg0' => $replace ? 'replace' : 'restore']);

    $link = $new->wg->getLink('wg0');
    expect($report['restored'])->toBe(['wg0'])
        ->and($report['not_started'])->toBe(['wg0' => 'wg-quick: failed to start wg0'])
        // What was restored is not thrown away: the keys, the peers, their client configs
        ->and($link->public_key)->toBe($old->wg->getLink('wg0')->public_key)
        ->and($link->up)->toBeFalse()
        ->and(array_keys($new->host->confPeers('wg0')))->toBe([$peers['plain']->public_key, $peers['custom']->public_key])
        ->and($new->wg->getPeerConfig('wg0', $peers['plain']->public_key))->toContain('Endpoint = new.example.test:51820')
        ->and($new->host->clients)->toHaveCount(2, 'The replaced link\'s client configs are gone')
        // Down for good, until the admin starts it
        ->and($new->host->interfaces)->toBe([])
        ->and($new->host->enabledUnits)->toBe([])
        ->and($new->host->firewall)->toBe([]);

    expect($new->wg->updateLink('wg0', ['up' => true])->up)->toBeTrue();
})->with('os')->with(['a new link' => false, 'in place of an existing one' => true]);

it('backs up a hand-written config but does not restore it', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->host->confs['office'] = handWrittenConf();

    $payload = $rig->backup->create();

    expect($rig->backup->links($payload)['office']['unmanaged'])->toBe(['Table', 'PostUp', 'comments', 'PersistentKeepalive'])
        ->and($rig->backup->links($payload)['wg0']['unmanaged'])->toBe([]);

    // Rebuilding it for another server would drop those settings
    $new = new Rig('linux');
    expect($new->backup->problems($payload, 'office'))->toHaveCount(1)
        ->and($new->backup->problems($payload, 'office')[0])->toContain("has settings this app doesn't manage (Table, PostUp, comments, PersistentKeepalive)")
        ->and(fn () => $new->backup->restore($payload, ['office' => 'restore']))->toThrow(ConflictException::class, "doesn't manage")
        ->and($new->host->files())->toBe([]);
});

it('never restores over an existing link by itself', function () {
    [$old] = backedUpServer('linux');
    $new = new Rig('linux');
    $new->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $link = $old->backup->create()['links']['wg0'];

    expect(fn () => $new->wg->restoreLink('wg0', $link['conf'], $link['clients'], true))->toThrow(ConflictException::class, 'Link already exists: wg0');
});

it('exports the stored client config of each peer', function () {
    [$rig, $peers] = backedUpServer('linux');

    $links = $rig->backup->create()['links'];

    expect(array_keys($links))->toBe(['wg0', 'wg1'])
        ->and($links['wg0']['up'])->toBeTrue()
        ->and($links['wg1']['up'])->toBeFalse()
        ->and(array_keys($links['wg0']['clients']))->toBe([KeyManager::pubkeyToSafe($peers['plain']->public_key), KeyManager::pubkeyToSafe($peers['custom']->public_key)]);
});

it('restores a backup whose configs still have the up line older versions wrote', function () {
    [$old] = backedUpServer('linux');
    $payload = $old->backup->create();
    foreach (['wg0', 'wg1'] as $name) {
        $payload['links'][$name]['conf'] = str_replace('# format = ', "# up = true\n# format = ", $payload['links'][$name]['conf']);
    }
    $new = new Rig('linux');

    // Whether a link runs was never read from that line: the backup says so itself
    expect($new->backup->problems($payload, 'wg0'))->toBe([])
        ->and($new->backup->restore($payload, ['wg0' => 'restore', 'wg1' => 'restore'])['restored'])->toBe(['wg0', 'wg1'])
        ->and($new->host->conf('wg0').$new->host->conf('wg1'))->not->toContain('# up')
        ->and([$new->wg->getLink('wg0')->up, $new->wg->getLink('wg1')->up])->toBe([true, false]);
});

it('restores what peers had of their own from a backup made before that was stored with them', function () {
    [$old, $peers] = backedUpServer('linux'); // one peer with its own DNS, 9.9.9.9
    $payload = $old->backup->create();
    // Then: no peer settings in the link config, and whole client configs in the backup
    $payload['links']['wg0']['conf'] = asFormat1($payload['links']['wg0']['conf']);
    foreach ([$peers['plain'], $peers['custom']] as $peer) {
        $payload['links']['wg0']['clients'][KeyManager::pubkeyToSafe($peer->public_key)] = $old->wg->getPeerConfig('wg0', $peer->public_key);
    }
    expect($payload['links']['wg0']['conf'])->not->toContain('9.9.9.9');
    $new = new Rig('linux', hostname: 'new.example.test');

    $new->backup->restore($payload, ['wg0' => 'restore']);

    expect($new->host->conf('wg0'))->toContain("# format = 2\n", "# dns = 9.9.9.9\nPublicKey = {$peers['custom']->public_key}\n")
        ->and($new->wg->getLink('wg0')->peers[0]->dns)->toBeNull()
        ->and($new->wg->getPeerConfig('wg0', $peers['custom']->public_key))->toContain("DNS = 9.9.9.9\n", 'Endpoint = new.example.test:51820')
        ->and($new->wg->getPeerConfig('wg0', $peers['plain']->public_key))->toContain("DNS = 8.8.8.8\n");
});

it('restores the keys of the peers, and the MTU and remotes of the link', function () {
    $old = new Rig('linux');
    $old->wg->createLink('wg0', '10.0.0.1/24', 51820, mtu: 1380);
    $peer = $old->wg->addPeer('wg0', remote: 'branch.example.com:51820');
    $new = new Rig('mac', hostname: 'new.example.test');

    $report = $new->backup->restore($old->backup->create(), ['wg0' => 'restore']);

    $link = $new->wg->getLink('wg0');
    expect($report['clients'])->toBe(1)
        ->and($link->mtu)->toBe(1380)
        ->and($link->peers[0]->remote)->toBe('branch.example.com:51820')
        ->and(array_values($new->host->clients)[0])->toContain("PrivateKey = {$peer->private_key}")->not->toContain('Endpoint')
        ->and($new->wg->getPeerConfig('wg0', $peer->public_key))->toContain("PrivateKey = {$peer->private_key}\n", 'Endpoint = new.example.test:51820', "MTU = 1380\n");
});

it('does not restore networks that cover an address this server needs itself', function () {
    $old = new Rig('linux');
    $old->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $old->wg->addPeer('wg0', networks: '192.168.50.0/24');
    $payload = $old->backup->create();
    // On the old server that was a branch office; here it is this server's own LAN
    $payload['links']['wg0']['conf'] = str_replace('192.168.50.0/24', '192.0.2.0/24', $payload['links']['wg0']['conf']);
    $new = new Rig('linux');

    expect($new->backup->problems($payload, 'wg0'))->toHaveCount(1)
        ->and($new->backup->problems($payload, 'wg0')[0])->toStartWith('192.0.2.0/24 covers 192.0.2.10, an address this server uses itself')
        ->and(fn () => $new->backup->restore($payload, ['wg0' => 'restore']))->toThrow(ConflictException::class, 'covers 192.0.2.10')
        ->and($new->host->files())->toBe([]);
});
