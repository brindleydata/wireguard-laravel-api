<?php

use App\Services\KeyManager;
use App\Services\Os\OsDriver;
use App\Services\Shell;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/*
 * The HTTP API through the real container wiring, with the host simulated for the current OS.
 */

beforeEach(function () {
    config(['wireguard.api_key' => 'test-key', 'wireguard.hostname' => 'vpn.example.test']);

    $shell = new FakeShell;
    $this->app->instance(Shell::class, $shell);

    $os = PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux';
    $this->host = new FakeHost($os, $shell, app(OsDriver::class)->configPath(), '/tmp');
    $this->auth = ['api-key' => 'test-key'];
});

it('runs a link and peer through their lifecycle', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)
        ->assertCreated()
        ->assertJsonPath('name', 'wg0')
        ->assertJsonPath('up', true)
        ->assertJsonPath('interface', $this->host->interfaceOf('wg0'));

    $peer = $this->postJson('/link/wg0/peers', [], $this->auth)
        ->assertCreated()
        ->assertJsonPath('allowed_ips', '10.0.0.2/32')
        ->json();
    $safe = KeyManager::pubkeyToSafe($peer['public_key']);

    $this->getJson('/link/wg0/peers', $this->auth)->assertOk()->assertJsonCount(1);
    $this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)
        ->assertOk()
        ->assertJsonPath('config', $peer['client_config']);

    $this->deleteJson("/link/wg0/peer/{$safe}", [], $this->auth)->assertOk();
    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();

    $this->getJson('/link/wg0', $this->auth)->assertNotFound();
    expect($this->host->files)->toBe([]);
});

it('rejects requests without the right API key', function () {
    $this->getJson('/links')->assertForbidden();
    $this->getJson('/links', ['api-key' => 'wrong'])->assertForbidden();
});

it('locks the API instead of opening it when no API key is set', function () {
    config(['wireguard.api_key' => '']);

    $this->getJson('/links')->assertForbidden();
    $this->getJson('/links', ['api-key' => ''])->assertForbidden();
    $this->getJson('/ip')->assertOk()->assertJsonPath('ipv4', '203.0.113.10'); // public routes still work
});

it('maps errors to status codes with a message', function () {
    $link = ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820];

    // Invalid input
    $this->postJson('/link', [...$link, 'dns' => "1.1.1.1\nPostUp = id"], $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', 'Value must not contain control characters or line breaks.');

    // The host fails: rolled back, reported with the command's error output
    $this->host->failNextStart = true;
    $this->postJson('/link', $link, $this->auth)
        ->assertInternalServerError()
        ->assertJsonPath('error', 'Failed to create link wg0: wg-quick: failed to start wg0');

    // Conflict with existing state
    $this->postJson('/link', $link, $this->auth)->assertCreated();
    $this->postJson('/link', $link, $this->auth)
        ->assertConflict()
        ->assertJsonPath('error', 'Link already exists: wg0');

    $this->deleteJson('/link/wg1', [], $this->auth)
        ->assertNotFound()
        ->assertJsonPath('error', 'Link does not exist: wg1');

    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();
});
