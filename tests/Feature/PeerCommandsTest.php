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
