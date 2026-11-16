<?php

use App\Exceptions\ConflictException;
use App\Exceptions\ErrorCode;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Services\KeyManager;
use Tests\Fakes\CommandFailed;
use Tests\Support\Rig;

/*
 * Adopting a config the app didn't write (WireGuard::adoptLink()), against a simulated Linux and
 * macOS host: one as the API before this one left it (legacyLink() in Pest.php), and ones written
 * by hand.
 */

afterEach(fn () => Rig::cleanup());

/** A rig with a legacy link, running as its owner started it (its own hooks ran) unless $up is false. */
function legacyRig(string $os, array $legacy, bool $up = true, string $name = 'pbx'): Rig
{
    $rig = new Rig($os);
    $rig->host->confs[$name] = $legacy['conf'];
    if ($up) {
        $rig->shell->run('sudo -n :helper up :name', ['name' => $name]);
    }

    return $rig;
}

/** The helper commands that change something, of those run since call number $from. */
function changesSince(Rig $rig, int $from): array
{
    return array_values(array_filter(
        array_column(array_slice($rig->shell->calls, $from), 'command'),
        fn (string $command) => preg_match('/ (peer-|link-key|conf-write|conf-delete|conf-adopt|client-write|client-delete|client-import|up |down |firewall-up|firewall-down)/', $command) === 1,
    ));
}

// ─── What is kept, dropped and applied ──────────────────────────────

it('adopts a legacy link in place: same key, port, address and peers, its hooks gone, the app\'s rules in their place', function (string $os) {
    $legacy = legacyLink(peers: 3, ifout: $os === 'mac' ? 'en0' : 'eth0');
    $rig = legacyRig($os, $legacy);
    $before = $rig->wg->getLink('pbx');
    expect($before->managed)->toBeFalse()
        ->and($rig->host->hooks['pbx'])->toContain('iptables -A FORWARD')
        ->and(fn () => $rig->wg->addPeer('pbx'))->toThrow(ConflictException::class, 'adopt it: wgla link:adopt pbx --dry-run');

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx', ['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16, 192.0.2.50', 'endpoint' => 'vpn.example.org']);

    // Nothing a client would notice
    expect($link->managed)->toBeTrue()
        ->and($link->up)->toBeTrue()
        ->and($link->public_key)->toBe($legacy['public_key'])->toBe($before->public_key)
        ->and($link->listen_port)->toBe(62990)
        ->and($link->address)->toBe('10.0.42.1/24')
        ->and(array_map(fn ($peer) => [$peer->public_key, $peer->allowed_ips], $link->peers))
        ->toBe(array_map(fn (array $peer) => [$peer['public_key'], "{$peer['ip']}/32"], $legacy['peers']))
        ->and($rig->host->runtimePeers('pbx'))->toBe(array_combine(array_column($legacy['peers'], 'public_key'), array_map(fn (array $peer) => "{$peer['ip']}/32", $legacy['peers'])));
    foreach ($legacy['peers'] as $peer) {
        expect($rig->host->conf('pbx'))->toContain("PublicKey = {$peer['public_key']}\nPresharedKey = {$peer['preshared_key']}\nAllowedIPs = {$peer['ip']}/32");
    }

    // Its own hooks ran one last time (its PostDown took its rules along), and are gone; the app's
    // rules are in place, held to where its NAT went
    expect($rig->host->hooks)->toBe([])
        ->and($rig->host->conf('pbx'))->not->toContain('iptables')->toContain('firewall-up', '# destinations = 10.20.0.0/16, 192.0.2.50/32', "PrivateKey = {$legacy['private_key']}\nListenPort = 62990")
        ->and($rig->host->firewall['pbx'])->toBe(['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16, 192.0.2.50/32'])
        ->and($link->firewall)->toBe('ok')
        ->and($link->destinations)->toBe('10.20.0.0/16, 192.0.2.50/32')
        ->and($link->endpoint)->toBe('vpn.example.org')
        ->and($rig->host->kept)->toBe([], 'The config it replaced is not kept once the link runs');

    expect($adoption)->toMatchArray([
        'dry_run' => false,
        'restarts' => true,
        'kept' => ['public_key' => $legacy['public_key'], 'listen_port' => 62990, 'address' => '10.0.42.1/24', 'address6' => null, 'peers' => 3],
        'dropped' => ['PostUp' => 1, 'PostDown' => 1],
        'warnings' => [],
    ])->and($adoption['applied'])->toMatchArray(['ifout' => $os === 'mac' ? 'en0' : 'eth0', 'forward' => true, 'nat' => true, 'inbound' => false, 'destinations' => '10.20.0.0/16, 192.0.2.50/32', 'endpoint' => 'vpn.example.org', 'mtu' => null]);

    // And it is a link like any other now
    $peer = $rig->wg->addPeer('pbx', name: 'new');
    expect($peer->allowed_ips)->toBe('10.0.42.5/32')
        ->and($rig->wg->updateLink('pbx', ['dns' => '1.1.1.1'])->dns)->toBe('1.1.1.1')
        ->and(array_keys($rig->host->confPeers('pbx')))->toBe([...array_column($legacy['peers'], 'public_key'), $peer->public_key]);
})->with('os');

it('adopts a stopped link without starting it', function (string $os) {
    $legacy = legacyLink();
    $rig = legacyRig($os, $legacy, up: false);
    $calls = count($rig->shell->calls);

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx', ['nat' => true]);

    expect($link->up)->toBeFalse()->and($link->managed)->toBeTrue()->and($link->nat)->toBeTrue()
        ->and($adoption['restarts'])->toBeFalse()
        ->and($rig->host->interfaceOf('pbx'))->toBeNull()
        ->and($rig->host->enabledUnits)->toBe([])
        ->and(changesSince($rig, $calls))->toBe(['sudo -n :helper conf-adopt :name', 'sudo -n :helper client-import :link', 'sudo -n :helper conf-adopt-done :name']);

    // It starts as the app's when it is started
    expect($rig->wg->updateLink('pbx', ['up' => true])->firewall)->toBe('ok');
})->with('os');

it('says what it would do, and does none of it, with dry_run', function (string $os, bool $up) {
    $legacy = legacyLink();
    $rig = legacyRig($os, $legacy, $up);
    $rig->host->clients['pbx/10.0.42.2'] = legacyClientConf($legacy['peers'][0], $legacy['public_key']);
    $state = fn () => [$rig->host->files(), $rig->host->interfaces, $rig->host->hooks, $rig->host->firewall, $rig->host->enabledUnits];
    $before = $state();
    $calls = count($rig->shell->calls);
    $settings = ['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16', 'dns' => '10.20.0.53', 'mtu' => 1380];

    $dry = $rig->wg->adoptLink('pbx', $settings, dry_run: true);

    expect($state())->toBe($before)
        ->and(changesSince($rig, $calls))->toBe([])
        ->and($rig->wg->getLink('pbx')->managed)->toBeFalse()
        ->and($dry['adoption']['dry_run'])->toBeTrue()
        ->and($dry['adoption']['restarts'])->toBe($up)
        ->and($dry['link']->managed)->toBeTrue()
        ->and($dry['link']->up)->toBe($up)
        ->and($dry['link']->nat)->toBeTrue()
        ->and($dry['link']->mtu)->toBe(1380)
        ->and($dry['link']->dns)->toBe('10.20.0.53')
        ->and(count($dry['link']->peers))->toBe(3);

    // The real call answers the same, but for what only it can know: whether its rules are in
    // place, and (macOS) the interface it runs as after its restart
    $real = $rig->wg->adoptLink('pbx', $settings);
    $comparable = fn (array $link) => array_diff_key($link, array_flip(['firewall', 'peers', 'interface']));
    expect($real['adoption'])->toBe([...$dry['adoption'], 'dry_run' => false])
        ->and($comparable($real['link']->toArray()))->toBe($comparable($dry['link']->toArray()))
        ->and(array_column($real['link']->toArray()['peers'], 'allowed_ips'))->toBe(array_column($dry['link']->toArray()['peers'], 'allowed_ips'));
})->with('os')->with(['running' => [true], 'stopped' => [false]]);

it('leaves a link without forward or NAT when none is asked for, and says so', function () {
    $rig = legacyRig('linux', legacyLink());

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx');

    // Its hooks are not read for what they did
    expect($link->forward)->toBeFalse()->and($link->nat)->toBeFalse()->and($link->destinations)->toBeNull()
        ->and($rig->host->firewall)->toBe([])
        ->and($adoption['warnings'])->toHaveCount(1)
        ->and($adoption['warnings'][0])->toContain('the link gets neither forward nor NAT rules');
});

it('reads a config as wg-quick does: keys in any case, comments anywhere, a key more than once', function () {
    $keys = new KeyManager;
    $branch = $keys->pubkey($keys->genkey());
    $rig = new Rig('linux');
    $rig->host->confs['site'] = implode("\n", [
        '# our site link',
        '[interface]',
        "privatekey={$keys->genkey()}   # the link's own",
        'LISTENPORT = 51901',
        'Address = 10.8.0.1/24',
        'MTU = 1400',
        'Table = auto',
        'SaveConfig = false',
        'PreUp = logger starting',
        'PostUp = ip rule add from 10.8.0.0/24 table 51',
        'PostUp = logger started',
        '',
        '[peer]   # the branch',
        "publickey = {$branch}",
        'allowedips = 192.168.9.5/24',
        'AllowedIPs = 10.8.0.2',
        'Endpoint = branch.example.com:51820',
        'PersistentKeepalive = 25',
        '# [Peer]',
        "# PublicKey = {$keys->pubkey($keys->genkey())}",
    ]);

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('site', ['forward' => true]);

    expect($link->listen_port)->toBe(51901)
        ->and($link->mtu)->toBe(1400)
        ->and($link->peers)->toHaveCount(1)
        // Each allowed IP as wg reads it, the peer's own address first
        ->and($link->peers[0])->public_key->toBe($branch)->allowed_ips->toBe('10.8.0.2/32, 192.168.9.0/24')->networks->toBe('192.168.9.0/24')->remote->toBe('branch.example.com:51820')
        ->and($adoption['dropped'])->toBe(['comments' => 5, 'Table' => 1, 'SaveConfig' => 1, 'PreUp' => 1, 'PostUp' => 2])
        ->and($rig->host->conf('site'))->toContain("MTU = 1400\n", "Endpoint = branch.example.com:51820\nPersistentKeepalive = 25")->not->toContain('logger', 'ip rule', 'our site link');
});

it('keeps what a config has of the app\'s own, unless asked otherwise', function () {
    // An app-written config someone added a line to: no longer managed, still the app's settings
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true, dns: '9.9.9.9', up: false, endpoint: 'vpn.example.org:443', destinations: '10.1.0.0/16');
    $named = $rig->wg->addPeer('wg0', name: 'laptop', dns: '1.1.1.1');
    $disabled = $rig->wg->addPeer('wg0', enabled: false);
    $rig->host->confs['wg0'] = str_replace("ListenPort = 51820\n", "ListenPort = 51820\nPostUp = logger up\n", $rig->host->conf('wg0'));
    expect($rig->wg->getLink('wg0')->managed)->toBeFalse();

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('wg0', ['nat' => false, 'dns' => null]);

    expect($link->managed)->toBeTrue()
        ->and([$link->forward, $link->nat, $link->dns, $link->endpoint, $link->destinations])->toBe([true, false, null, 'vpn.example.org:443', '10.1.0.0/16'])
        ->and($link->peers[0])->name->toBe('laptop')->dns->toBe('1.1.1.1')
        ->and($link->peers[1])->public_key->toBe($disabled->public_key)->enabled->toBeFalse()
        ->and($adoption['keys'])->toBe(['stored' => [$named->public_key, $disabled->public_key], 'imported' => [], 'own' => []])
        ->and($adoption['dropped'])->toBe(['PostUp' => 1]);
});

// ─── Peers' private keys ────────────────────────────────────────────

it('takes peers\' private keys over from the client configs the older API kept, and says whose', function (string $os) {
    $legacy = legacyLink(peers: 4);
    $rig = legacyRig($os, $legacy);
    [$with_file, $own, $another, $stored] = $legacy['peers'];
    // The older API kept a client config per peer, named by its address. One is gone, one is
    // of a peer that no longer exists, one peer has its key stored the app's way already.
    $rig->host->clients['pbx/10.0.42.2'] = legacyClientConf($with_file, $legacy['public_key']);
    $rig->host->clients['pbx/10.0.42.4'] = legacyClientConf($another, $legacy['public_key']);
    $rig->host->clients['pbx/10.0.42.99'] = legacyClientConf(['private_key' => (new KeyManager)->genkey(), 'preshared_key' => (new KeyManager)->genpsk(), 'ip' => '10.0.42.99'], $legacy['public_key']);
    $rig->host->clients['pbx/'.KeyManager::pubkeyToSafe($stored['public_key'])] = "PrivateKey = {$stored['private_key']}\n";
    $files = array_keys($rig->host->clients);

    $adoption = $rig->wg->adoptLink('pbx', ['endpoint' => 'vpn.example.org'])['adoption'];

    expect($adoption['keys'])->toBe(['stored' => [$stored['public_key']], 'imported' => [$with_file['public_key'], $another['public_key']], 'own' => [$own['public_key']]]);

    // Imported: a complete client config, as for any peer the app made (and so a QR code of it)
    foreach ([$with_file, $another, $stored] as $peer) {
        expect($rig->wg->getPeerConfig('pbx', $peer['public_key'], with_key: true))
            ->toContain("PrivateKey = {$peer['private_key']}\n", "Address = {$peer['ip']}/32\n", "PresharedKey = {$peer['preshared_key']}\n", "PublicKey = {$legacy['public_key']}\n", 'Endpoint = vpn.example.org:62990');
    }
    // A key of its own: the config without the PrivateKey line, no QR code
    expect($rig->wg->getPeerConfig('pbx', $own['public_key']))->toContain("Address = {$own['ip']}/32\n")->not->toContain('PrivateKey')
        ->and(fn () => $rig->wg->peerConfigOrFail('pbx', $own['public_key'], with_key: true))->toThrow(InvalidArgumentException::class, "isn't stored here")
        // The old files stay as they were; the key of a peer that isn't one was not taken
        ->and(array_values(array_diff(array_keys($rig->host->clients), $files)))->toBe(['pbx/'.KeyManager::pubkeyToSafe($with_file['public_key']), 'pbx/'.KeyManager::pubkeyToSafe($another['public_key'])]);
})->with('os');

it('never shows a private or preshared key in what it answers', function () {
    $legacy = legacyLink();
    $rig = legacyRig('linux', $legacy);
    $rig->host->clients['pbx/10.0.42.2'] = legacyClientConf($legacy['peers'][0], $legacy['public_key']);

    foreach ([true, false] as $dry_run) {
        $result = $rig->wg->adoptLink('pbx', ['forward' => true], $dry_run);
        $answer = json_encode([...$result['link']->toArray(), 'adoption' => $result['adoption']]);

        expect($answer)->not->toContain($legacy['private_key'])->not->toContain('iptables');
        foreach ($legacy['peers'] as $peer) {
            expect($answer)->not->toContain($peer['private_key'])->not->toContain($peer['preshared_key']);
        }
    }
});

// ─── A link that doesn't come up ────────────────────────────────────

it('puts the previous config back and runs it as before when the link does not start', function (string $os) {
    $legacy = legacyLink();
    $rig = legacyRig($os, $legacy);
    $rig->host->clients['pbx/10.0.42.2'] = legacyClientConf($legacy['peers'][0], $legacy['public_key']);
    $files = [$rig->host->confs, $rig->host->clients, $rig->host->kept];
    // The link stops, and then doesn't start with its new config
    $rig->shell->failOnce('sudo -n :helper up :name', message: 'wg-quick: failed to start pbx');

    expect(fn () => $rig->wg->adoptLink('pbx', ['forward' => true, 'nat' => true]))
        ->toThrow(SystemException::class, 'The change to link pbx could not be applied and was undone: wg-quick: failed to start pbx');

    // As it was: its own config, running, with what its own hooks set up, and no key kept for it
    expect([$rig->host->confs, $rig->host->clients, $rig->host->kept])->toBe($files)
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf'])
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($rig->host->hooks['pbx'])->toContain('iptables -A FORWARD')
        ->and($rig->host->firewall)->toBe([])
        ->and($rig->wg->getLink('pbx'))->managed->toBeFalse()->up->toBeTrue()
        ->and(array_keys($rig->host->runtimePeers('pbx')))->toBe(array_column($legacy['peers'], 'public_key'));

    // And it can be asked again
    expect($rig->wg->adoptLink('pbx', ['forward' => true])['link']->managed)->toBeTrue();
})->with('os');

it('says so when putting the previous config back fails too', function () {
    $rig = legacyRig('linux', legacyLink());
    $rig->shell->failOnce('sudo -n :helper up :name', message: 'wg-quick: failed to start pbx')
        ->failOnce('sudo -n :helper conf-adopt-undo :name', message: 'mv: Read-only file system');

    expect(fn () => $rig->wg->adoptLink('pbx'))
        ->toThrow(SystemException::class, 'The change to link pbx could not be applied, and undoing it failed too (check the link with wg:link pbx): wg-quick: failed to start pbx');
});

it('leaves a running link running when the helper does not take its new config', function () {
    $legacy = legacyLink();
    $rig = legacyRig('linux', $legacy);
    $calls = count($rig->shell->calls);

    // Checked before anything stops
    $rig->shell->failOnce('sudo -n :helper conf-check :name', message: 'wgla-helper: not allowed in a link config: X');
    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(SystemException::class, 'not allowed in a link config')
        ->and(changesSince($rig, $calls))->toBe([]);

    // And if it only refuses when it is to write it: started again with its own config
    $rig->shell->failOnce('sudo -n :helper conf-adopt :name', message: 'wgla-helper: input larger than 1048576 bytes');
    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(SystemException::class, 'could not be applied and was undone: wgla-helper: input larger')
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf'])
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($rig->host->hooks)->toHaveKey('pbx');
});

it('does not adopt a link it cannot stop', function () {
    $legacy = legacyLink();
    $rig = legacyRig('linux', $legacy);

    $rig->shell->failOnce('sudo -n :helper down :name', message: 'Failed to stop wg-quick@pbx.service');
    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(SystemException::class, 'Link pbx could not be stopped, so it was not adopted, and runs on as it did: Failed to stop wg-quick@pbx.service')
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf'])
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull();

    // One that something else than systemd started stays up when its unit is stopped: that is for
    // whoever started it to put right, not a failure of the host
    $rig->shell->on('sudo -n :helper down :name', fn () => '');
    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(ConflictException::class, 'Link pbx still runs after it was stopped the way this app stops links')
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf'])
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($rig->host->kept)->toBe([]);
});

it('adopts a link whose own PostDown failed: wg-quick has taken it down by then', function (string $os) {
    $legacy = legacyLink();
    $rig = legacyRig($os, $legacy);
    // Its hook deletes rules another tool flushed long ago: wg-quick fails, after it removed the interface
    $rig->shell->on('sudo -n :helper down :name', function () use ($rig) {
        unset($rig->host->interfaces[$rig->host->interfaceOf('pbx')], $rig->host->names['pbx']);
        $rig->host->enabledUnits = [];

        throw new CommandFailed('iptables: Bad rule (does a matching rule exist in that chain?).');
    });

    // Left down, it would be an outage for a hook that had nothing left to do
    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx', ['forward' => true]);

    expect($link)->managed->toBeTrue()->up->toBeTrue()
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($rig->host->firewall['pbx'])->toBe(['forward' => true, 'nat' => false])
        ->and($adoption['warnings'])->toHaveCount(1)
        ->and($adoption['warnings'][0])->toStartWith('The link stopped, but not cleanly')->toContain('iptables: Bad rule');
})->with('os');

// ─── What can't be adopted ──────────────────────────────────────────

it('refuses a config with what it has no place for, naming it, and changes nothing', function (string $extra, string $named, ?string $peer_line = null, ?string $instead_of = null) {
    $legacy = legacyLink(extra: $extra);
    $conf = match (true) {
        $peer_line === null => $legacy['conf'],
        $instead_of !== null => str_replace($instead_of, $peer_line, $legacy['conf']),
        default => preg_replace('/^(AllowedIPs = .*)$/m', "$1\n{$peer_line}", $legacy['conf'], 1),
    };
    $rig = legacyRig('linux', ['conf' => $conf] + $legacy);
    $calls = count($rig->shell->calls);

    foreach ([true, false] as $dry_run) {
        try {
            $rig->wg->adoptLink('pbx', ['forward' => true], $dry_run);
            $e = null;
        } catch (ConflictException $e) {
        }

        expect($e)->not->toBeNull()
            ->and($e->errorCode)->toBe(ErrorCode::NOT_ADOPTABLE)
            ->and($e->getMessage())->toStartWith("Link pbx can't be adopted as it is: its config has what the app has no place for, or can't read ({$named}).");
    }
    expect($rig->host->conf('pbx'))->toBe($conf)
        ->and(changesSince($rig, $calls))->toBe([]);
})->with([
    'a routing table of its own' => ['Table = off', 'Table'],
    'DNS for the server itself' => ['DNS = 1.1.1.1', 'DNS'],
    'a firewall mark' => ['FwMark = 0x1234', 'FwMark'],
    'a setting nobody knows' => ['Foo = bar', 'unknown settings'],
    'several of them' => ["Table = 1234\nDNS = 1.1.1.1\nFwMark = 51", 'Table, DNS, FwMark'],
    'a second address' => ['Address = 10.0.43.1/24', 'Address'],
    'a second private key' => ['PrivateKey = '.str_repeat('A', 43).'=', 'PrivateKey'],
    'a keepalive the server sends a peer' => ['', 'PersistentKeepalive', 'PersistentKeepalive = 25'],
    'a peer at an address that is none' => ['', 'Endpoint', 'Endpoint = nowhere'],
    'a keepalive of its own for a peer it connects to' => ['', 'PersistentKeepalive', "Endpoint = 198.51.100.7:51820\nPersistentKeepalive = 15"],
    'a peer setting nobody knows' => ['', 'unknown settings', 'Bar = 1'],
    'a peer that has no address in the link' => ['', "a peer without an address of its own (a /32) in the link's subnet", 'AllowedIPs = 192.168.7.0/24', 'AllowedIPs = 10.0.42.2/32'],
    'allowed IPs that are none' => ['', 'AllowedIPs', 'AllowedIPs = somewhere'],
]);

it('refuses a config without what a link needs, and one that says a peer twice', function () {
    $legacy = legacyLink();
    $refusal = function (string $conf) {
        $rig = legacyRig('linux', ['conf' => $conf], up: false);
        try {
            $rig->wg->adoptLink('pbx');
        } catch (ConflictException $e) {
            return $e->getMessage();
        }

        return null;
    };

    expect($refusal(preg_replace('/^ListenPort = .*\n/m', '', $legacy['conf'])))->toContain('(no ListenPort)')
        ->and($refusal(preg_replace('/^PrivateKey = .*\n/m', '', $legacy['conf'])))->toContain('(no PrivateKey)')
        ->and($refusal(preg_replace('/^Address = .*\n/m', '', $legacy['conf'])))->toContain('(no Address)')
        ->and($refusal(str_replace('ListenPort = 62990', 'ListenPort = 99999', $legacy['conf'])))->toContain('(ListenPort)')
        ->and($refusal(str_replace('Address = 10.0.42.1/24', 'Address = 10.0.42.1', $legacy['conf'])))->toContain('(Address)')
        ->and($refusal($legacy['conf']."\n[Peer]\nPublicKey = {$legacy['peers'][0]['public_key']}\nAllowedIPs = 10.0.42.77/32\n"))->toContain('(PublicKey)')
        ->and($refusal($legacy['conf']."\n[Peer]\nPublicKey = {$legacy['peers'][0]['public_key']}x\nAllowedIPs = 10.0.42.77/32\n"))->toContain('(PublicKey)')
        ->and($refusal("[Peer]\nPublicKey = {$legacy['peers'][0]['public_key']}\nAllowedIPs = 10.0.42.77/32\n"))->toContain('no [Interface]');
});

it('names what is in the way without quoting it', function () {
    $legacy = legacyLink(extra: 'PrivateKey = '.($second = (new KeyManager)->genkey())."\nDNS = secret.internal.example");
    $rig = legacyRig('linux', $legacy, up: false);

    try {
        $rig->wg->adoptLink('pbx');
    } catch (ConflictException $e) {
    }

    expect($e->getMessage())->toContain('PrivateKey, DNS')->not->toContain($second)->not->toContain($legacy['private_key'])->not->toContain('secret.internal');
});

it('has nothing to adopt in a link the app manages, and none where there is no config', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->host->addUnmanagedInterface('wg9');
    $conf = $rig->host->conf('wg0');
    $code = function (Closure $adopt) {
        try {
            $adopt();
        } catch (ConflictException|NotFoundException $e) {
            return $e->errorCode;
        }

        return null;
    };

    // Also with a dry run, which says what the real call would
    expect($code(fn () => $rig->wg->adoptLink('wg0', ['nat' => true])))->toBe(ErrorCode::ALREADY_MANAGED)
        ->and($code(fn () => $rig->wg->adoptLink('wg0', dry_run: true)))->toBe(ErrorCode::ALREADY_MANAGED)
        ->and($code(fn () => $rig->wg->adoptLink('wg9')))->toBe(ErrorCode::UNMANAGED_INTERFACE)
        ->and($code(fn () => $rig->wg->adoptLink('nope')))->toBe(ErrorCode::LINK_NOT_FOUND)
        ->and(fn () => $rig->wg->adoptLink('no.such.link'))->toThrow(InvalidArgumentException::class)
        ->and($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->wg->getLink('wg0')->nat)->toBeFalse();
});

it('checks what it is asked to apply like any change to a link, before it changes anything', function (array $params, string $exception, string $message, bool $dry_run) {
    $legacy = legacyLink();
    $rig = legacyRig('linux', $legacy);
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821);
    $calls = count($rig->shell->calls);

    expect(fn () => $rig->wg->adoptLink('pbx', $params, $dry_run))->toThrow($exception, $message)
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf'])
        ->and(changesSince($rig, $calls))->toBe([]);
})->with([
    'an outbound interface that is not there' => [['ifout' => 'eth7'], InvalidArgumentException::class, 'Output interface does not exist: eth7'],
    'an endpoint that is none' => [['endpoint' => 'not an endpoint'], InvalidArgumentException::class, 'Invalid endpoint'],
    'allowed IPs that are none' => [['allowed_ips' => '10.0.0.0/33'], InvalidArgumentException::class, 'Invalid allowed IP or CIDR'],
    'destinations that are none' => [['destinations' => '10.20.0.0/16, pbx.example.com'], InvalidArgumentException::class, 'Invalid allowed IP or CIDR'],
    'everything as a destination' => [['destinations' => '0.0.0.0/0'], InvalidArgumentException::class, 'is every address'],
    'an MTU too small' => [['mtu' => 100], InvalidArgumentException::class, 'Invalid MTU'],
    'what the server does not allow' => [['allow_default_route' => true], ConflictException::class, "This server doesn't let links allow that (allow_default_route)"],
])->with(['for real' => [false], 'as a dry run' => [true]]);

it('refuses a config that clashes with another link, or routes what its peers may not', function () {
    $legacy = legacyLink();
    $clashes = function (string $conf, array $params = []) {
        $rig = new Rig('linux');
        $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, up: false);
        $rig->wg->addPeer('wg1', networks: '192.168.50.0/24');
        $rig->host->confs['pbx'] = $conf;
        try {
            $rig->wg->adoptLink('pbx', $params, dry_run: true);
        } catch (ConflictException $e) {
            return [$e->errorCode, $e->getMessage()];
        }

        return null;
    };

    expect($clashes(str_replace('ListenPort = 62990', 'ListenPort = 51821', $legacy['conf'])))->toBe(['conflict', 'Port 51821 is already used by link wg1'])
        ->and($clashes(str_replace('10.0.42.', '10.1.0.', $legacy['conf']))[1])->toBe('Subnet 10.1.0.1/24 overlaps link wg1 (10.1.0.1/24)')
        ->and($clashes(str_replace('AllowedIPs = 10.0.42.2/32', 'AllowedIPs = 10.0.42.2/32, 192.168.50.0/25', $legacy['conf']))[1])->toBe('192.168.50.0/25 overlaps 192.168.50.0/24 of link wg1')
        ->and($clashes(str_replace('AllowedIPs = 10.0.42.2/32', 'AllowedIPs = 10.0.42.2/32, 0.0.0.0/0', $legacy['conf']))[1])->toStartWith('0.0.0.0/0 is a default route')
        ->and($clashes($legacy['conf']))->toBeNull();
});

it('does not start a link whose peer\'s name does not resolve', function () {
    $legacy = legacyLink();
    $conf = preg_replace('/^(AllowedIPs = .*)$/m', "$1\nEndpoint = branch.example.com:51820", $legacy['conf'], 1);
    $rig = legacyRig('linux', ['conf' => $conf]);
    $rig->host->unresolvable = ['branch.example.com'];

    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(ConflictException::class, "branch.example.com, the remote of peer {$legacy['peers'][0]['public_key']} of link pbx, doesn't resolve now")
        ->and($rig->host->conf('pbx'))->toBe($conf)
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull();

    $rig->host->unresolvable = [];
    expect($rig->wg->adoptLink('pbx')['link']->peers[0]->remote)->toBe('branch.example.com:51820');
});

// ─── A dual-stack link ──────────────────────────────────────────────

it('adopts a dual-stack link whose peers have the IPv6 address the app would give them, and no other', function () {
    $legacy = legacyLink(peers: 2);
    $dual = str_replace(['Address = 10.0.42.1/24', 'AllowedIPs = 10.0.42.2/32', 'AllowedIPs = 10.0.42.3/32'],
        ['Address = 10.0.42.1/24,FD42::1/64', 'AllowedIPs = FD42::2/128, 10.0.42.2/32', 'AllowedIPs = 10.0.42.3/32, fd42::3/128, 192.168.7.0/24'], $legacy['conf']);
    $rig = legacyRig('linux', ['conf' => $dual], up: false);

    $link = $rig->wg->adoptLink('pbx')['link'];

    expect($link->address6)->toBe('fd42::1/64')
        ->and($link->peers[0]->allowed_ips)->toBe('10.0.42.2/32, fd42::2/128')
        ->and($link->peers[1])->allowed_ips->toBe('10.0.42.3/32, fd42::3/128, 192.168.7.0/24')->networks->toBe('192.168.7.0/24')
        ->and($rig->wg->getPeerConfig('pbx', $legacy['peers'][0]['public_key']))->toContain('Address = 10.0.42.2/32, fd42::2/128');

    // An address in the prefix that its client config would not have, or none where it would have one
    $other = fn (string $conf) => str_replace(['10.0.42.', 'ListenPort = 62990', 'fd42:'], ['10.0.43.', 'ListenPort = 62991', 'fd43:'], $conf);
    $rig->host->confs['odd'] = $other(str_replace('fd42::3/128', 'fd42::33/128', $dual));
    expect(fn () => $rig->wg->adoptLink('odd'))->toThrow(ConflictException::class, "(a peer without the IPv6 address its IPv4 one gives it in the link's prefix, or with another)");
    $rig->host->confs['odd'] = $other(str_replace('AllowedIPs = FD42::2/128, 10.0.42.2/32', 'AllowedIPs = 10.0.42.2/32', $dual));
    expect(fn () => $rig->wg->adoptLink('odd'))->toThrow(ConflictException::class, "(a peer without the IPv6 address its IPv4 one gives it in the link's prefix, or with another)")
        ->and($rig->wg->getLink('odd')->managed)->toBeFalse();
});

it('says where the running interface and the config differ: the restart makes it the config again', function () {
    $legacy = legacyLink(peers: 2);
    $rig = legacyRig('linux', $legacy);
    // Added with `wg set` and never saved; and one taken off the interface that is still in the config
    $rig->host->interfaces['pbx']['peers'][$stray = (new KeyManager)->pubkey((new KeyManager)->genkey())] = ['psk' => null, 'allowed_ips' => '10.0.42.9/32'];
    unset($rig->host->interfaces['pbx']['peers'][$legacy['peers'][1]['public_key']]);

    $adoption = $rig->wg->adoptLink('pbx', ['forward' => true], dry_run: true)['adoption'];

    // Neither is silent: one loses its access, the other gets it back
    expect($adoption['warnings'])->toBe([
        "1 of the peers on the running interface are not in the config: they are not adopted, and the restart drops them, as any restart of the link would ({$stray}).",
        "1 of the peers in the config are not on the running interface (taken off it, or never loaded): they are adopted, and the restart brings them back, as any restart of the link would ({$legacy['peers'][1]['public_key']}).",
    ])->and($adoption['kept']['peers'])->toBe(2);

    $real = $rig->wg->adoptLink('pbx', ['forward' => true]);
    expect($real['adoption']['warnings'])->toBe($adoption['warnings'])
        ->and(array_keys($rig->host->runtimePeers('pbx')))->toBe(array_column($legacy['peers'], 'public_key'));
});

// ─── A config wg-quick saves itself (the API before this one: SaveConfig = true) ───

it('adopts what the interface has, not the stale file, of a running link whose config wg-quick saves', function (string $os) {
    $keys = new KeyManager;
    $legacy = legacyLink(peers: 2, extra: 'SaveConfig = true', ifout: $os === 'mac' ? 'en0' : 'eth0');
    $rig = legacyRig($os, $legacy);
    $iface = $rig->host->interfaceOf('pbx');
    [$kept, $removed] = $legacy['peers'];
    // As that API worked: a peer added and one removed with `wg set`, which only the interface
    // knows until wg-quick saves it when the link stops. A removed peer must stay removed.
    $added = ['public_key' => $keys->pubkey($keys->genkey()), 'preshared_key' => $keys->genpsk()];
    $rig->host->interfaces[$iface]['peers'][$added['public_key']] = ['psk' => $added['preshared_key'], 'allowed_ips' => '10.0.42.7/32'];
    unset($rig->host->interfaces[$iface]['peers'][$removed['public_key']]);
    $rig->host->setPeerStats('pbx', $kept['public_key'], '198.51.100.7:40123', time() - 30, 1000, 2000);

    $dry = $rig->wg->adoptLink('pbx', ['nat' => true], dry_run: true);
    expect(array_map(fn ($peer) => $peer->public_key, $dry['link']->peers))->toBe([$kept['public_key'], $added['public_key']])
        ->and($rig->host->conf('pbx'))->toBe($legacy['conf']);

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx', ['nat' => true]);

    expect(array_map(fn ($peer) => [$peer->public_key, $peer->allowed_ips, $peer->remote], $link->peers))
        ->toBe([[$kept['public_key'], '10.0.42.2/32', null], [$added['public_key'], '10.0.42.7/32', null]])
        ->and($rig->host->conf('pbx'))->toContain("PublicKey = {$added['public_key']}\nPresharedKey = {$added['preshared_key']}\nAllowedIPs = 10.0.42.7/32")
        ->not->toContain($removed['public_key'])->not->toContain('SaveConfig')->not->toContain('Endpoint')
        ->and($link->public_key)->toBe($legacy['public_key'])
        ->and($link->listen_port)->toBe(62990)
        ->and($adoption['kept']['peers'])->toBe(2)
        // What wg-quick saved of where the peer was last seen is no setting: dropped with the rest
        ->and($adoption['dropped'])->toEqual(['PostUp' => 1, 'PostDown' => 1, 'SaveConfig' => 1, 'Endpoint' => 1])
        // (which the dry run knew, of an interface it only looked at)
        ->and($dry['adoption']['dropped'])->toEqual($adoption['dropped'])
        ->and($rig->host->hooks)->toBe([]);
})->with('os');

it('adopts the file of a stopped link whose config wg-quick saved, without the endpoints in it', function () {
    $legacy = legacyLink(peers: 2, extra: 'SaveConfig = true');
    $saved = preg_replace('/^(AllowedIPs = .*)$/m', "$1\nEndpoint = 198.51.100.7:40123", $legacy['conf']);
    $rig = legacyRig('linux', ['conf' => $saved], up: false);

    ['link' => $link, 'adoption' => $adoption] = $rig->wg->adoptLink('pbx');

    expect(array_map(fn ($peer) => $peer->remote, $link->peers))->toBe([null, null])
        ->and($adoption['dropped'])->toBe(['PostUp' => 1, 'PostDown' => 1, 'SaveConfig' => 1, 'Endpoint' => 2])
        ->and($rig->host->conf('pbx'))->not->toContain('Endpoint', 'PersistentKeepalive');
});

it('keeps what only the comments of a config knew when wg-quick rewrites it at the stop', function (string $os) {
    // An app-written config someone added SaveConfig to: wg-quick writes it anew from the interface
    // when the link stops, without the app's settings, its peers' names, or a peer it disabled
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true, dns: '9.9.9.9', keepalive: 15, endpoint: 'vpn.example.org:443', destinations: '10.1.0.0/16');
    $named = $rig->wg->addPeer('wg0', name: 'laptop', dns: '1.1.1.1');
    $disabled = $rig->wg->addPeer('wg0', name: 'old phone', enabled: false);
    $rig->wg->updateLink('wg0', ['up' => false]);
    $rig->host->confs['wg0'] = str_replace("ListenPort = 51820\n", "ListenPort = 51820\nSaveConfig = true\n", $rig->host->conf('wg0'));
    $rig->shell->run('sudo -n :helper up :name', ['name' => 'wg0']);
    expect($rig->wg->getLink('wg0')->managed)->toBeFalse();

    $dry = $rig->wg->adoptLink('wg0', dry_run: true);
    $real = $rig->wg->adoptLink('wg0');

    // What the dry run answered is what was done: nothing of it was made anew from the saved file
    expect($real['adoption'])->toBe([...$dry['adoption'], 'dry_run' => false])
        ->and($real['adoption']['applied'])->toMatchArray(['forward' => true, 'nat' => true, 'destinations' => '10.1.0.0/16', 'endpoint' => 'vpn.example.org:443', 'dns' => '9.9.9.9', 'keepalive' => 15])
        ->and($real['adoption']['kept']['peers'])->toBe(2)
        ->and($real['adoption']['keys']['stored'])->toBe([$named->public_key, $disabled->public_key])
        ->and($real['link']->peers[0])->name->toBe('laptop')->dns->toBe('1.1.1.1')->enabled->toBeTrue()
        ->and($real['link']->peers[1])->public_key->toBe($disabled->public_key)->name->toBe('old phone')->enabled->toBeFalse()
        ->and($real['link'])->managed->toBeTrue()->firewall->toBe('ok')
        // Still held to its destinations
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true, 'destinations' => '10.1.0.0/16'])
        ->and(array_keys($rig->host->runtimePeers('wg0')))->toBe([$named->public_key])
        ->and($rig->host->conf('wg0'))->not->toContain('SaveConfig');
})->with('os');

it('refuses a running link whose config wg-quick is about to write a firewall mark into, before it stops it', function () {
    $legacy = legacyLink(extra: 'SaveConfig = true');
    $rig = legacyRig('linux', $legacy);
    $rig->host->interfaces['pbx']['fwmark'] = '0xca6c'; // as wg-quick sets it for a peer with a default route
    $calls = count($rig->shell->calls);

    foreach ([true, false] as $dry_run) {
        expect(fn () => $rig->wg->adoptLink('pbx', dry_run: $dry_run))->toThrow(ConflictException::class, '(FwMark)');
    }
    expect(changesSince($rig, $calls))->toBe([])
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull();
});

it('starts a link again as it was when its peers changed between the look at its interface and its stop', function () {
    $legacy = legacyLink(peers: 1, extra: 'SaveConfig = true');
    $rig = legacyRig('linux', $legacy);
    // Something else adds a peer to the interface in that moment: wg-quick saves it, the plan doesn't have it
    $rig->shell->on('sudo -n :helper down :name', function () use ($rig) {
        $rig->host->confs['pbx'] .= "\n[Peer]\nPublicKey = ".str_repeat('B', 43)."=\nAllowedIPs = 10.0.42.9/32\n";
        unset($rig->host->interfaces['pbx']);
        $rig->host->enabledUnits = [];

        return '';
    });

    // Adopted as planned, it would be gone without a word
    expect(fn () => $rig->wg->adoptLink('pbx'))->toThrow(SystemException::class, 'could not be applied and was undone: its peers changed while it was being adopted')
        ->and($rig->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($rig->host->conf('pbx'))->toContain('iptables', str_repeat('B', 43))
        ->and($rig->host->kept)->toBe([]);
});
