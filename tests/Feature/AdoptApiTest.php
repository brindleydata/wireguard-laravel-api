<?php

use App\Services\KeyManager;
use App\Services\Shell;
use App\Services\WireGuard;
use Illuminate\Support\Facades\Artisan;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/*
 * Adopting a config the app didn't write, and a link's destinations, through the HTTP API and the
 * CLI, with the host simulated for the current OS.
 */

beforeEach(function () {
    config(['wireguard.api_key' => 'test-key', 'wireguard.helper' => base_path('bin/wgla-helper')]);

    $shell = new FakeShell;
    $this->app->instance(Shell::class, $shell);
    $this->host = new FakeHost(PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux', $shell);
    $this->auth = ['api-key' => 'test-key'];
    $this->uplink = PHP_OS_FAMILY === 'Darwin' ? 'en0' : 'eth0';

    // A link the API before this one left, running as its owner started it, with a client config
    // it kept for one of its three peers
    $this->legacy = legacyLink(ifout: $this->uplink);
    $this->host->confs['pbx'] = $this->legacy['conf'];
    $this->host->clients['pbx/10.0.42.2'] = legacyClientConf($this->legacy['peers'][0], $this->legacy['public_key']);
    $shell->run('sudo -n :helper up :name', ['name' => 'pbx']);
});

it('shows a legacy link, refuses to change it, and adopts it with POST /link/{name}/adopt', function () {
    $this->getJson('/link/pbx', $this->auth)->assertOk()->assertJsonPath('managed', false)->assertJsonPath('up', true)->assertJsonCount(3, 'peers');
    $this->patchJson('/link/pbx', ['nat' => true], $this->auth)->assertConflict()->assertJsonPath('code', 'unmanaged_config');

    $adopted = $this->postJson('/link/pbx/adopt', ['forward' => true, 'nat' => true, 'destinations' => ['10.20.0.0/16', '192.0.2.50'], 'endpoint' => 'vpn.example.org'], $this->auth)
        ->assertOk()
        ->assertJsonPath('managed', true)
        ->assertJsonPath('up', true)
        ->assertJsonPath('public_key', $this->legacy['public_key'])
        ->assertJsonPath('listen_port', 62990)
        ->assertJsonPath('address', '10.0.42.1/24')
        ->assertJsonPath('forward', true)
        ->assertJsonPath('nat', true)
        ->assertJsonPath('destinations', '10.20.0.0/16, 192.0.2.50/32')
        ->assertJsonPath('firewall', 'ok')
        ->assertJsonPath('adoption.dry_run', false)
        ->assertJsonPath('adoption.restarts', true)
        ->assertJsonPath('adoption.kept', ['public_key' => $this->legacy['public_key'], 'listen_port' => 62990, 'address' => '10.0.42.1/24', 'address6' => null, 'peers' => 3])
        ->assertJsonPath('adoption.dropped', ['PostUp' => 1, 'PostDown' => 1])
        ->assertJsonPath('adoption.applied.ifout', $this->uplink)
        ->assertJsonPath('adoption.applied.destinations', '10.20.0.0/16, 192.0.2.50/32')
        // Whose private key is here: the one the older API kept a client config of. The others are keys of their own.
        ->assertJsonPath('adoption.keys', ['stored' => [], 'imported' => [$this->legacy['peers'][0]['public_key']], 'own' => [$this->legacy['peers'][1]['public_key'], $this->legacy['peers'][2]['public_key']]])
        ->assertJsonPath('adoption.warnings', [])
        ->json();

    // The link as GET /link/{name} answers it, and the adoption next to it
    expect(array_diff_key($adopted, ['adoption' => 0]))->toBe($this->getJson('/link/pbx', $this->auth)->json())
        ->and(array_column($adopted['peers'], 'public_key'))->toBe(array_column($this->legacy['peers'], 'public_key'))
        ->and(array_column($adopted['peers'], 'allowed_ips'))->toBe(['10.0.42.2/32', '10.0.42.3/32', '10.0.42.4/32'])
        ->and($this->host->hooks)->toBe([])
        ->and($this->host->firewall['pbx'])->toBe(['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16, 192.0.2.50/32']);

    // A complete config (and QR code) of the peer whose key was taken over, and one without PrivateKey of the others
    [$imported, $own] = array_map(fn (array $peer) => KeyManager::pubkeyToSafe($peer['public_key']), $this->legacy['peers']);
    expect($this->getJson("/link/pbx/peer/{$imported}/config", $this->auth)->assertOk()->json('config'))
        ->toContain("PrivateKey = {$this->legacy['peers'][0]['private_key']}\n", "Address = 10.0.42.2/32\n", "PublicKey = {$this->legacy['public_key']}\n", 'Endpoint = vpn.example.org:62990');
    $this->get("/link/pbx/peer/{$imported}/qr", $this->auth)->assertOk();
    expect($this->getJson("/link/pbx/peer/{$own}/config", $this->auth)->assertOk()->json('config'))->toContain("Address = 10.0.42.3/32\n")->not->toContain('PrivateKey');
    $this->getJson("/link/pbx/peer/{$own}/qr", $this->auth)->assertUnprocessable()->assertJsonPath('code', 'invalid_input');

    // It is a link like any other now, and there is nothing left to adopt
    $this->patchJson('/link/pbx', ['dns' => '10.20.0.53'], $this->auth)->assertOk()->assertJsonPath('client.dns', '10.20.0.53');
    $this->postJson('/link/pbx/peers', ['name' => 'new'], $this->auth)->assertCreated()->assertJsonPath('allowed_ips', '10.0.42.5/32');
    $this->postJson('/link/pbx/adopt', ['nat' => false], $this->auth)->assertConflict()->assertJsonPath('code', 'already_managed');
    $this->postJson('/link/pbx/adopt', ['dry_run' => true], $this->auth)->assertConflict()->assertJsonPath('code', 'already_managed');
    $this->getJson('/link/pbx', $this->auth)->assertJsonPath('nat', true);
});

it('answers a dry run as the real call, and changes nothing', function () {
    $state = fn () => [$this->host->files(), $this->host->interfaces, $this->host->hooks, $this->host->firewall];
    $before = $state();
    $body = ['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16', 'ifout' => $this->uplink, 'keepalive' => 20, 'mtu' => 1380];

    $dry = $this->postJson('/link/pbx/adopt', [...$body, 'dry_run' => true], $this->auth)
        ->assertOk()
        ->assertJsonPath('managed', true)
        ->assertJsonPath('nat', true)
        ->assertJsonPath('mtu', 1380)
        ->assertJsonPath('client.keepalive', 20)
        ->assertJsonPath('adoption.dry_run', true)
        ->assertJsonPath('adoption.restarts', true)
        ->assertJsonPath('adoption.keys.imported', [$this->legacy['peers'][0]['public_key']])
        ->json();

    expect($state())->toBe($before);
    $this->getJson('/link/pbx', $this->auth)->assertJsonPath('managed', false)->assertJsonPath('nat', false);

    // The same shape, and the same in it but what only the real call can know
    $real = $this->postJson('/link/pbx/adopt', $body, $this->auth)->assertOk()->json();
    $comparable = fn (array $answer) => [array_diff_key($answer, array_flip(['adoption', 'peers', 'firewall', 'interface'])), array_diff_key($answer['adoption'], ['dry_run' => 0])];
    expect(array_keys($real))->toBe(array_keys($dry))
        ->and(array_keys($real['adoption']))->toBe(array_keys($dry['adoption']))
        ->and($comparable($real))->toBe($comparable($dry));
});

it('never answers with a key that is not the caller\'s to have, nor with what a config says', function () {
    foreach ([['dry_run' => true], []] as $body) {
        $answer = $this->postJson('/link/pbx/adopt', $body, $this->auth)->assertOk()->getContent();

        expect($answer)->not->toContain($this->legacy['private_key'])->not->toContain('PrivateKey')->not->toContain('preshared')->not->toContain('iptables');
        foreach ($this->legacy['peers'] as $peer) {
            expect($answer)->not->toContain($peer['private_key'])->not->toContain($peer['preshared_key']);
        }
    }
});

it('refuses what it cannot carry over, by name, and fields it does not know', function () {
    $conf = $this->host->conf('pbx');

    $this->postJson('/link/pbx/adopt', ['forwrad' => true], $this->auth)->assertUnprocessable()->assertJsonPath('code', 'invalid_input')
        ->assertJsonPath('error', fn (string $error) => str_starts_with($error, 'Unknown field: forwrad. Known: ifout, forward, nat, inbound, destinations, allowed_ips, dns, keepalive, mtu, endpoint, allow_default_route, allow_own_networks, dry_run.'));
    // What an adoption keeps is not the caller's to change with it
    foreach (['address' => '10.9.0.1/24', 'port' => 51820, 'private_key' => (new KeyManager)->genkey(), 'up' => false] as $field => $value) {
        $this->postJson('/link/pbx/adopt', [$field => $value], $this->auth)->assertUnprocessable()->assertJsonPath('code', 'invalid_input');
    }
    $this->postJson('/link/pbx/adopt', ['ifout' => 'eth7', 'dry_run' => true], $this->auth)->assertUnprocessable()->assertJsonPath('error', 'Output interface does not exist: eth7');
    $this->postJson('/link/pbx/adopt', ['destinations' => [], 'dry_run' => true], $this->auth)->assertUnprocessable()->assertJsonPath('code', 'invalid_input');
    $this->postJson('/link/pbx/adopt', ['mtu' => 'big'], $this->auth)->assertUnprocessable()->assertJsonPath('errors.mtu.0', 'The mtu field must be an integer.');

    $this->host->confs['pbx'] = str_replace("ListenPort = 62990\n", "ListenPort = 62990\nTable = off\nDNS = 10.20.0.53\n", $conf);
    foreach ([['dry_run' => true], []] as $body) {
        $this->postJson('/link/pbx/adopt', $body, $this->auth)->assertConflict()->assertJsonPath('code', 'not_adoptable')
            ->assertJsonPath('error', fn (string $error) => str_contains($error, '(Table, DNS)') && ! str_contains($error, '10.20.0.53'));
    }

    expect($this->host->conf('pbx'))->toContain('Table = off')
        ->and($this->host->interfaceOf('pbx'))->not->toBeNull()
        ->and($this->host->hooks)->toHaveKey('pbx');
});

it('answers 500 and runs the link as before when it does not come up with its new config', function () {
    $this->host->shell->failOnce('sudo -n :helper up :name', message: 'wg-quick: failed to start pbx');

    $this->postJson('/link/pbx/adopt', ['forward' => true, 'nat' => true], $this->auth)
        ->assertInternalServerError()
        ->assertJsonPath('code', 'system_error')
        ->assertJsonPath('error', 'The change to link pbx could not be applied and was undone: wg-quick: failed to start pbx');

    expect($this->host->conf('pbx'))->toBe($this->legacy['conf'])
        ->and($this->host->hooks)->toHaveKey('pbx')
        ->and($this->host->firewall)->toBe([])
        ->and($this->host->kept)->toBe([])
        ->and(array_keys($this->host->clients))->toBe(['pbx/10.0.42.2']);
    $this->getJson('/link/pbx', $this->auth)->assertOk()->assertJsonPath('up', true)->assertJsonPath('managed', false)->assertJsonCount(3, 'peers');
});

// ─── Destinations ───────────────────────────────────────────────────

it('takes a link\'s destinations as a list or an array, shows them, and takes them away with null', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'forward' => true, 'nat' => true, 'destinations' => ['10.20.0.5/16', '2001:db8:a::/48']], $this->auth)
        ->assertCreated()
        ->assertJsonPath('destinations', '10.20.0.0/16, 2001:db8:a::/48')
        ->assertJsonPath('firewall', 'ok');
    expect($this->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16, 2001:db8:a::/48']);

    $this->patchJson('/link/wg0', ['destinations' => '10.30.0.0/16 ,192.0.2.50'], $this->auth)->assertOk()->assertJsonPath('destinations', '10.30.0.0/16, 192.0.2.50/32');
    // Leaving them out keeps them; null is anywhere again
    $this->patchJson('/link/wg0', ['dns' => '1.1.1.1'], $this->auth)->assertOk()->assertJsonPath('destinations', '10.30.0.0/16, 192.0.2.50/32');
    $this->getJson('/link/wg0', $this->auth)->assertJsonPath('destinations', '10.30.0.0/16, 192.0.2.50/32')->assertJsonPath('firewall', 'ok');
    $this->patchJson('/link/wg0', ['destinations' => null], $this->auth)->assertOk()->assertJsonPath('destinations', null);
    expect($this->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true]);

    // Neither nowhere nor everything: an empty list could mean either, and null says anywhere
    foreach ([[], ['10.20.0.0/16', 7], ['a' => '10.20.0.0/16'], 7, '0.0.0.0/0', 'pbx.example.com', "10.20.0.0/16\nPostUp = id"] as $destinations) {
        $this->patchJson('/link/wg0', ['destinations' => $destinations], $this->auth)->assertUnprocessable()->assertJsonPath('code', 'invalid_input');
    }
    $this->getJson('/link/wg0', $this->auth)->assertJsonPath('destinations', null);
});

it('reports and repairs the rules of a link that only has destinations', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'destinations' => '10.20.0.0/16'], $this->auth)
        ->assertCreated()->assertJsonPath('forward', false)->assertJsonPath('nat', false)->assertJsonPath('firewall', 'ok');
    unset($this->host->firewall['wg0']);

    $this->getJson('/link/wg0', $this->auth)->assertJsonPath('firewall', 'missing');
    $this->postJson('/link/wg0/repair', [], $this->auth)->assertOk()->assertJsonPath('firewall', 'ok');
    expect($this->host->firewall['wg0'])->toBe(['forward' => false, 'nat' => false, 'destinations' => '10.20.0.0/16']);
});

// ─── The CLI ────────────────────────────────────────────────────────

it('adopts from the command line: first what it would do, then for real, and as JSON what the API answers', function () {
    $key = $this->legacy['peers'][0]['public_key'];

    $this->artisan('wg:link', ['link' => 'pbx'])->expectsOutputToContain('A config can be taken under management: wgla link:adopt pbx --dry-run')->assertSuccessful();
    $this->artisan('wg:link:adopt', ['link' => 'pbx', '--dry-run' => true, '--forward' => 'true', '--nat' => 'true', '--destinations' => '10.20.0.0/16'])
        ->expectsOutputToContain('Adopting link pbx would do this (nothing was changed):')
        ->expectsOutputToContain("Kept: public key {$this->legacy['public_key']}, port 62990, address 10.0.42.1/24, 3 peers with their keys and allowed IPs")
        ->expectsOutputToContain('Dropped: PostUp ×1, PostDown ×1')
        ->expectsOutputToContain("Applied: ifout {$this->uplink}, forward on, nat on, inbound off, destinations 10.20.0.0/16, endpoint vpn.example.test")
        ->expectsOutputToContain('Private keys of its peers: 1 taken over from the client configs an older API kept, 2 not here (keys of their own: their client configs come without PrivateKey, and without a QR code)')
        ->expectsOutputToContain("  Taken over: {$key}")
        ->expectsOutputToContain("  Not here: {$this->legacy['peers'][1]['public_key']}")
        ->expectsOutputToContain('The link runs: it would restart')
        ->doesntExpectOutputToContain('iptables')
        ->assertSuccessful();
    expect($this->host->conf('pbx'))->toBe($this->legacy['conf']);

    // What the API answers for the same, as JSON
    config(['wireguard.api_key' => 'test-key']);
    $dry = cliAnswer('wg:link:adopt', ['link' => 'pbx', '--dry-run' => true, '--nat' => 'true', '--destinations' => '10.20.0.0/16']);
    expect($dry)->toBe($this->postJson('/link/pbx/adopt', ['dry_run' => true, 'nat' => true, 'destinations' => '10.20.0.0/16'], $this->auth)->json());

    // Without forward or NAT it says so, and a mistyped option is no option
    $this->artisan('wg:link:adopt', ['link' => 'pbx', '--dry-run' => true])->expectsOutputToContain('the link gets neither forward nor NAT rules')->assertSuccessful();
    $this->artisan('wg:link:adopt', ['link' => 'pbx', '--forward' => 'treu'])->expectsOutputToContain('--forward must be true or false')->assertFailed();

    $this->artisan('wg:link:adopt', ['link' => 'pbx', '--forward' => 'true', '--nat' => 'true', '--destinations' => '10.20.0.0/16'])
        ->expectsOutputToContain('Adopted link pbx')
        ->expectsOutputToContain('The link was restarted with its new config.')
        ->assertSuccessful();
    expect(app(WireGuard::class)->getLink('pbx'))->managed->toBeTrue()->destinations->toBe('10.20.0.0/16')->firewall->toBe('ok');
    $this->artisan('wg:link', ['link' => 'pbx'])->expectsOutputToContain('Destinations: 10.20.0.0/16')->doesntExpectOutputToContain('wgla link:adopt')->assertSuccessful();
    $this->artisan('wg:link:adopt', ['link' => 'pbx'])->expectsOutputToContain('is managed already')->assertFailed();
});

it('sets and takes away a link\'s destinations from the command line', function () {
    $this->artisan('wg:link:create', ['link' => 'wg0', 'ip' => '10.0.0.1/24', '--port' => '51820', '--nat' => 'true', '--destinations' => '10.20.0.0/16,192.0.2.50'])
        ->expectsOutputToContain('Destinations: 10.20.0.0/16, 192.0.2.50/32')
        ->assertSuccessful();
    $this->artisan('wg:link:update', ['link' => 'wg0', '--destinations' => '10.30.0.0/16'])->expectsOutputToContain('Destinations: 10.30.0.0/16')->assertSuccessful();
    expect($this->host->firewall['wg0']['destinations'])->toBe('10.30.0.0/16');

    $this->artisan('wg:link:update', ['link' => 'wg0', '--destinations' => '0.0.0.0/0'])->expectsOutputToContain('is every address')->assertFailed();
    $this->artisan('wg:link:update', ['link' => 'wg0', '--destinations' => ''])->expectsOutputToContain('Destinations: anywhere')->assertSuccessful();
    expect(app(WireGuard::class)->getLink('wg0')->destinations)->toBeNull();
});

/** A command's --json answer. */
function cliAnswer(string $command, array $arguments = []): array
{
    Artisan::call($command, [...$arguments, '--json' => true]);

    return json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
}
