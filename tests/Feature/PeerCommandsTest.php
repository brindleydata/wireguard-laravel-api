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
