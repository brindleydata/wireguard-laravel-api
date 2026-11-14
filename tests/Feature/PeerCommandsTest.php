<?php

use App\Services\Shell;
use App\Services\WireGuard;
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
