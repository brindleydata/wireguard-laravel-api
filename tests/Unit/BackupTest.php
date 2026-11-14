<?php

use App\DTOs\PeerInfo;
use App\Exceptions\ConflictException;
use App\Services\KeyManager;
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
    expect($taken->backup->clashes($payload, 'wg0'))->toBe(['prefix fd12::1/64 overlaps wg5 (fd12::5/64)']);
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

    expect($new->backup->clashes($payload, 'wg0'))->toBe(['port 51820 is used by wg9', 'subnet 10.0.0.1/24 overlaps wg9 (10.0.0.200/24)'])
        ->and($new->backup->clashes($payload, 'wg0', ignore: ['wg9']))->toBe([])
        ->and($new->backup->clashes($payload, 'wg1'))->toBe([])
        ->and(fn () => $new->backup->restore($payload, ['wg0' => 'restore']))->toThrow(ConflictException::class, 'Port 51820 is already used by link wg9');
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
