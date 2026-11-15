<?php

use App\Services\KeyManager;
use App\Services\Os\OsDriver;
use App\Services\Server;
use App\Services\Shell;
use App\Services\WireGuard;
use Illuminate\Support\Facades\Artisan;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/*
 * The peer commands with the host simulated for the current OS.
 */

beforeEach(function () {
    config(['wireguard.hostname' => 'vpn.example.test', 'wireguard.helper' => base_path('bin/wgla-helper')]);
    $shell = new FakeShell;
    $this->app->instance(Shell::class, $shell);
    $this->host = new FakeHost(PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux', $shell);
    app(WireGuard::class)->createLink('wg0', '10.0.0.1/24', 51820);
});

it('creates a named peer with networks and shows its config as a QR code', function () {
    $this->artisan('wg:peer:create', ['link' => 'wg0', '--name' => 'branch', '--networks' => '192.168.1.0/24', '--qr' => true])
        ->expectsOutputToContain('Allowed IPs: 10.0.0.2/32, 192.168.1.0/24')
        ->expectsOutputToContain('▀')
        ->assertSuccessful();

    $key = app(WireGuard::class)->getLink('wg0')->peers[0]->public_key;
    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => $key, '--qr' => true])
        ->expectsOutputToContain('▀')
        ->doesntExpectOutputToContain('PrivateKey')
        ->assertSuccessful();
    $this->artisan('wg:link:peers', ['link' => 'wg0'])->expectsOutputToContain('branch  10.0.0.2/32')->assertSuccessful();
});

it('disables and enables a peer, and removes its name', function () {
    $key = app(WireGuard::class)->addPeer('wg0', name: 'laptop')->public_key;

    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $key, '--enabled' => 'false'])
        ->expectsOutputToContain('Enabled: no')
        ->assertSuccessful();
    $this->artisan('wg:link:peers', ['link' => 'wg0'])->expectsOutputToContain("laptop  10.0.0.2/32  {$key}  disabled");

    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $key, '--enabled' => 'true', '--name' => ''])
        ->expectsOutputToContain('Enabled: yes')
        ->assertSuccessful();
    expect(app(WireGuard::class)->getLink('wg0')->peers[0])->name->toBeNull()->enabled->toBeTrue();
});

it('takes a link\'s or peer\'s own client setting out with an empty option', function () {
    $wg = app(WireGuard::class);
    $wg->updateLink('wg0', ['dns' => '9.9.9.9', 'keepalive' => 15]);
    $key = $wg->addPeer('wg0')->public_key;
    $wg->updatePeer('wg0', $key, ['dns' => '1.1.1.1']);

    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $key, '--dns' => ''])
        ->expectsOutputToContain('DNS = 9.9.9.9')
        ->assertSuccessful();

    // "" is not 0 seconds
    $this->artisan('wg:link:update', ['link' => 'wg0', '--dns' => '', '--keepalive' => ''])->assertSuccessful();
    expect($wg->getPeerConfig('wg0', $key))->toContain("DNS = 8.8.8.8\n", 'PersistentKeepalive = 25');

    $this->artisan('wg:link:update', ['link' => 'wg0', '--keepalive' => '0'])->assertSuccessful();
    expect($wg->getPeerConfig('wg0', $key))->toContain('PersistentKeepalive = 0');
});

it('shows a client config for either form of the public key', function () {
    $key = app(WireGuard::class)->addPeer('wg0')->public_key;

    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => rtrim(strtr($key, '+/', '-_'), '=')])
        ->expectsOutputToContain('PrivateKey = ')
        ->assertSuccessful();
    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => 'not-a-key'])->assertFailed();
});

it('refuses a mistyped option instead of reading it as false or 0', function (string $command, array $options, string $error) {
    $wg = app(WireGuard::class);
    $key = $wg->addPeer('wg0')->public_key;
    $arguments = str_contains($command, 'peer') ? ['link' => 'wg0', 'pubkey' => $key] : ['link' => 'wg0'];

    $this->artisan($command, [...$arguments, ...$options])->expectsOutputToContain($error)->assertFailed();

    // "--up=treu" used to bring the link down
    expect($wg->getLink('wg0')->up)->toBeTrue()
        ->and($wg->getLink('wg0')->peers[0]->enabled)->toBeTrue()
        ->and($wg->getLink('wg0')->listen_port)->toBe(51820);
})->with([
    ['wg:link:update', ['--up' => 'treu'], '--up must be true or false, not "treu".'],
    ['wg:link:update', ['--forward' => 'enable'], '--forward must be true or false'],
    ['wg:link:update', ['--port' => '51821x'], '--port must be a whole number, not "51821x".'],
    ['wg:link:update', ['--keepalive' => 'abc'], '--keepalive must be a whole number'],
    ['wg:peer:update', ['--enabled' => 'no way'], '--enabled must be true or false'],
    ['wg:peer:update', ['--keepalive' => '-5'], '--keepalive must be a whole number'],
]);

it('still takes the usual words for true and false', function () {
    $this->artisan('wg:link:update', ['link' => 'wg0', '--forward' => 'yes', '--nat' => '1'])->expectsOutputToContain('Forward: enabled')->assertSuccessful();
    $this->artisan('wg:link:update', ['link' => 'wg0', '--up' => 'off'])->expectsOutputToContain('Up: no')->assertSuccessful();
    $this->artisan('wg:link:create', ['link' => 'wg1', 'ip' => '10.1.0.1/24', '--up' => 'flase'])->expectsOutputToContain('--up must be true or false')->assertFailed();

    expect(app(WireGuard::class)->listLinks())->toBe(['wg0']);
});

it('moves a link and its peers, and gives a peer its own keepalive', function () {
    $wg = app(WireGuard::class);
    $key = $wg->addPeer('wg0')->public_key;

    $this->artisan('wg:link:update', ['link' => 'wg0', '--address' => '10.5.0.1/24'])->expectsOutputToContain('--move-peers')->assertFailed();
    $this->artisan('wg:link:update', ['link' => 'wg0', '--address' => '10.5.0.1/24', '--move-peers' => true])
        ->expectsOutputToContain('Address: 10.5.0.1/24')
        ->assertSuccessful();
    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $key, '--keepalive' => '7'])
        ->expectsOutputToContain('PersistentKeepalive = 7')
        ->assertSuccessful();

    expect($wg->getLink('wg0')->peers[0])->allowed_ips->toBe('10.5.0.2/32')->keepalive->toBe(7);
});

it('gives a peer new keys from the command line', function () {
    $wg = app(WireGuard::class);
    $old = $wg->addPeer('wg0', name: 'laptop');

    $this->artisan('wg:peer:rekey', ['link' => 'wg0', 'pubkey' => $old->public_key, '--qr' => true])
        ->expectsOutputToContain('(laptop)')
        ->expectsOutputToContain("It was {$old->public_key}: the client config with that key no longer works.")
        ->expectsOutputToContain('PrivateKey = ')
        ->expectsOutputToContain('▀')
        ->assertSuccessful();

    expect($wg->getLink('wg0')->peers[0]->public_key)->not->toBe($old->public_key)
        ->and($wg->getPeerConfig('wg0', $old->public_key))->toBeNull();
    $this->artisan('wg:peer:rekey', ['link' => 'wg0', 'pubkey' => $old->public_key])->expectsOutputToContain('Peer not found')->assertFailed();
});

it('sets a link\'s MTU and a peer\'s remote, and shows what a link hands out', function () {
    $wg = app(WireGuard::class);

    $this->artisan('wg:link:update', ['link' => 'wg0', '--mtu' => '1380', '--dns' => '9.9.9.9'])->expectsOutputToContain('MTU: 1380')->assertSuccessful();
    $this->artisan('wg:peer:create', ['link' => 'wg0', '--name' => 'branch', '--remote' => 'branch.example.com:51820'])
        ->expectsOutputToContain('MTU = 1380')
        ->assertSuccessful();
    $this->artisan('wg:link', ['link' => 'wg0'])
        ->expectsOutputToContain('MTU: 1380')
        ->expectsOutputToContain('Client DNS: 9.9.9.9')
        ->expectsOutputToContain('Client keepalive: (default)')
        ->expectsOutputToContain('Remote: branch.example.com:51820')
        ->assertSuccessful();

    $key = $wg->getLink('wg0')->peers[0]->public_key;
    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $key, '--remote' => ''])->assertSuccessful();
    $this->artisan('wg:link:update', ['link' => 'wg0', '--mtu' => ''])->expectsOutputToContain('MTU: (default)')->assertSuccessful();

    expect($wg->getLink('wg0'))->mtu->toBeNull()
        ->and($wg->getLink('wg0')->peers[0]->remote)->toBeNull();
});

it('says when a link\'s firewall rules are missing, and repairs them', function () {
    $wg = app(WireGuard::class);
    $wg->updateLink('wg0', ['forward' => true]);
    unset($this->host->firewall['wg0']);

    $this->artisan('wg:link', ['link' => 'wg0'])->expectsOutputToContain('Its firewall rules are missing. Put them back with: wgla link:repair wg0')->assertSuccessful();
    $this->artisan('wg:link:repair', ['link' => 'wg0'])->expectsOutputToContain('The firewall rules of wg0 are in place.')->assertSuccessful();
    $this->artisan('wg:link:repair', ['link' => 'nope'])->expectsOutputToContain('Link does not exist: nope')->assertFailed();

    expect($this->host->firewall)->toHaveKey('wg0');
});

// ─── The same things as the API ─────────────────────────────────────

/** A command's --json answer. */
function cliJson(string $command, array $arguments = []): array
{
    Artisan::call($command, [...$arguments, '--json' => true]);

    return json_decode(Artisan::output(), true, flags: JSON_THROW_ON_ERROR);
}

it('prints with --json exactly what the API returns', function () {
    config(['wireguard.api_key' => 'k']);
    $auth = ['api-key' => 'k'];
    $wg = app(WireGuard::class);
    $wg->updateLink('wg0', ['forward' => true, 'dns' => '9.9.9.9', 'mtu' => 1380]);
    $key = $wg->addPeer('wg0', name: 'branch', networks: '192.168.1.0/24', remote: 'branch.example.com:51820')->public_key;
    $wg->addPeer('wg0');
    $safe = KeyManager::pubkeyToSafe($key);

    expect(cliJson('wg:links'))->toBe($this->getJson('/links', $auth)->json())
        ->and(cliJson('wg:link', ['link' => 'wg0']))->toBe($this->getJson('/link/wg0', $auth)->json())
        ->and(cliJson('wg:link:peers', ['link' => 'wg0']))->toBe($this->getJson('/link/wg0/peers', $auth)->json());

    // A peer with its client config: the API has those as two routes
    $peer = cliJson('wg:peer', ['link' => 'wg0', 'pubkey' => $key]);
    expect(array_diff_key($peer, ['client_config' => 0]))->toBe($this->getJson("/link/wg0/peer/{$safe}", $auth)->json())
        ->and($peer['client_config'])->toBe($this->getJson("/link/wg0/peer/{$safe}/config", $auth)->json('config'));

    // Status, public IPs and interfaces in one
    $this->host->shell->otherwise(fn () => '0');
    $status = cliJson('wg:status');
    expect(array_diff_key($status, ['ip' => 0, 'interfaces' => 0, 'default' => 0]))->toBe($this->getJson('/status', $auth)->json())
        ->and($status['ip'])->toBe($this->getJson('/ip', $auth)->json())
        ->and(array_intersect_key($status, ['interfaces' => 0, 'default' => 0]))->toBe($this->getJson('/interfaces', $auth)->json());
});

it('answers changes with --json like the API does', function () {
    $link = cliJson('wg:link:create', ['link' => 'wg1', 'ip' => '10.1.0.1/24', '--port' => '51821', '--forward' => 'true']);
    expect($link)->toMatchArray(['name' => 'wg1', 'listen_port' => 51821, 'forward' => true, 'firewall' => 'ok'])->not->toHaveKey('private_key');

    expect(cliJson('wg:link:update', ['link' => 'wg1', '--mtu' => '1400']))->toMatchArray(['name' => 'wg1', 'mtu' => 1400])
        ->and(cliJson('wg:link:repair', ['link' => 'wg1'])['firewall'])->toBe('ok');

    // A new peer comes with its private key and client config, as from POST …/peers
    $peer = cliJson('wg:peer:create', ['link' => 'wg1', '--name' => 'laptop', '--qr' => true]);
    expect($peer)->toMatchArray(['name' => 'laptop', 'allowed_ips' => '10.1.0.2/32'])
        ->and($peer['client_config'])->toContain("PrivateKey = {$peer['private_key']}\n");

    expect(cliJson('wg:peer:update', ['link' => 'wg1', 'pubkey' => $peer['public_key'], '--enabled' => 'false']))->toMatchArray(['name' => 'laptop', 'enabled' => false]);
    $rekeyed = cliJson('wg:peer:rekey', ['link' => 'wg1', 'pubkey' => $peer['public_key']]);
    expect($rekeyed['public_key'])->not->toBe($peer['public_key'])->and($rekeyed)->toHaveKey('private_key');

    expect(cliJson('wg:peer:delete', ['link' => 'wg1', 'pubkey' => $rekeyed['public_key']]))->toBe(['message' => 'Removed peer from wg1'])
        ->and(cliJson('wg:link:delete', ['link' => 'wg1']))->toBe(['message' => 'Deleted link: wg1'])
        ->and(cliJson('wg:link:update', ['link' => 'wg0']))->toBe(['message' => 'No options given: nothing to update.']);
});

it('fails with --json as {"error": …} and a non-zero exit code', function (string $command, array $arguments, string $error) {
    $code = Artisan::call($command, [...$arguments, '--json' => true]);

    expect($code)->toBe(1)
        ->and(json_decode(Artisan::output(), true))->toBe(['error' => $error]);
})->with([
    ['wg:link', ['link' => 'nope'], 'Link does not exist: nope'],
    ['wg:link:update', ['link' => 'wg0', '--up' => 'treu'], '--up must be true or false, not "treu".'],
    ['wg:link:create', ['link' => 'wg0', 'ip' => '10.9.0.1/24'], 'Link already exists: wg0'],
    ['wg:peer', ['link' => 'wg0', 'pubkey' => 'not-a-key'], 'Peer not-a-key not found on wg0.'],
    ['wg:peer:create', ['link' => 'wg0', '--ip' => '10.5.0.2'], "Peer IP 10.5.0.2 is not within the interface's network range (10.0.0.1/24)."],
]);

it('does not say deleted for what is still there', function () {
    // An interface something else started: not this app's to stop
    $this->host->addUnmanagedInterface('wg9');
    $this->artisan('wg:link:delete', ['link' => 'wg9'])
        ->expectsOutputToContain('wg9 is a running WireGuard interface without a config here')
        ->doesntExpectOutputToContain('Deleted')
        ->assertFailed();

    // A config the host didn't delete
    app(Shell::class)->on('sudo -n :helper conf-delete :name', fn () => throw new CommandFailed('rm: cannot remove: Read-only file system'));
    $code = Artisan::call('wg:link:delete', ['link' => 'wg0', '--json' => true]);

    expect($code)->toBe(1)
        ->and(json_decode(Artisan::output(), true)['error'])->toContain('Read-only file system')
        ->and(app(WireGuard::class)->listLinks())->toBe(['wg0', 'wg9']);
});

it('takes a public key in either form in every peer command', function () {
    $wg = app(WireGuard::class);
    $key = $wg->addPeer('wg0', name: 'laptop')->public_key;
    $safe = KeyManager::pubkeyToSafe($key); // as in the API's routes

    $this->artisan('wg:peer:update', ['link' => 'wg0', 'pubkey' => $safe, '--name' => 'renamed'])->expectsOutputToContain("Updated peer {$key} (renamed)")->assertSuccessful();
    $new = cliJson('wg:peer:rekey', ['link' => 'wg0', 'pubkey' => $safe])['public_key'];
    $this->artisan('wg:peer:delete', ['link' => 'wg0', 'pubkey' => KeyManager::pubkeyToSafe($new)])->assertSuccessful();

    expect($wg->getLink('wg0')->peers)->toBe([]);
});

it('shows a peer with its details above its client config', function () {
    $wg = app(WireGuard::class);
    $key = $wg->addPeer('wg0', name: 'branch', networks: '192.168.1.0/24', remote: 'branch.example.com:51820')->public_key;
    $wg->updatePeer('wg0', $key, ['dns' => '1.1.1.1']);

    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => $key])
        ->expectsOutputToContain("Peer {$key} (branch)")
        ->expectsOutputToContain('Allowed IPs: 10.0.0.2/32, 192.168.1.0/24')
        ->expectsOutputToContain('Networks behind it: 192.168.1.0/24')
        ->expectsOutputToContain('Remote: branch.example.com:51820')
        ->expectsOutputToContain('Own client settings: dns 1.1.1.1')
        ->expectsOutputToContain('State: never connected')
        ->expectsOutputToContain('DNS = 1.1.1.1')
        ->assertSuccessful();

    // One whose private key isn't stored here is shown all the same
    $this->host->clients = [];
    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => $key])->expectsOutputToContain('It has no client config')->assertSuccessful();
    $this->artisan('wg:peer', ['link' => 'wg0', 'pubkey' => $key, '--qr' => true])->expectsOutputToContain('no client config')->assertFailed();
});

it('names the release in wg:status as it is tagged', function (string $version) {
    $this->host->shell->otherwise(fn () => '0');
    config(['app.version' => $version, 'app.name' => 'WGLA']);
    app()->forgetInstance(Server::class);

    // "vv1.2.3" is what a real update showed: the tag has its v already
    $this->artisan('wg:status')->expectsOutput("WGLA {$version}")->assertSuccessful();
})->with(['v1.2.3', 'd891d88', 'dev']);

it('fails wg:status when the root helper is not usable, as /health answers 503', function () {
    $this->host->shell->otherwise(fn () => '0');

    $this->artisan('wg:status')->expectsOutputToContain('Root helper: ok')->expectsOutputToContain('(links go out through ')->assertSuccessful();

    config(['wireguard.helper' => '/nonexistent/wgla-helper']);
    app()->forgetInstance(OsDriver::class);
    app()->forgetInstance(Server::class);

    $this->artisan('wg:status')->expectsOutputToContain('Root helper: not installed')->assertFailed();
    $this->getJson('/health')->assertStatus(503);
});
