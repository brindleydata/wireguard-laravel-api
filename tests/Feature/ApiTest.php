<?php

use App\Services\KeyManager;
use App\Services\Server;
use App\Services\Shell;
use Illuminate\Support\Env;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/*
 * The HTTP API through the real container wiring, with the host simulated for the current OS.
 */

beforeEach(function () {
    config([
        'wireguard.api_key' => 'test-key',
        'wireguard.hostname' => 'vpn.example.test',
        // "Installed" helper = the bundled one, so the drift check passes
        'wireguard.helper' => base_path('bin/wgla-helper'),
    ]);

    $shell = new FakeShell;
    $this->app->instance(Shell::class, $shell);

    $os = PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux';
    $this->host = new FakeHost($os, $shell);
    $this->auth = ['api-key' => 'test-key'];
});

it('runs a link and peer through their lifecycle', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)
        ->assertCreated()
        ->assertJsonPath('name', 'wg0')
        ->assertJsonPath('up', true)
        ->assertJsonPath('interface', $this->host->interfaceOf('wg0'))
        ->assertJsonMissingPath('private_key'); // the server's private key never leaves the host

    $peer = $this->postJson('/link/wg0/peers', [], $this->auth)
        ->assertCreated()
        ->assertJsonPath('allowed_ips', '10.0.0.2/32')
        ->json();
    $safe = KeyManager::pubkeyToSafe($peer['public_key']);

    $this->getJson('/link/wg0/peers', $this->auth)->assertOk()->assertJsonCount(1)
        ->assertJsonPath('0.connected', false)
        ->assertJsonPath('0.latest_handshake_at', null)
        ->assertJsonPath('0.transfer_rx', 0);
    $this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)
        ->assertOk()
        ->assertJsonPath('config', $peer['client_config']);

    $this->deleteJson("/link/wg0/peer/{$safe}", [], $this->auth)->assertOk();
    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();

    $this->getJson('/link/wg0', $this->auth)->assertNotFound();
    expect($this->host->files())->toBe([]);
});

it('reports a missing root helper as a 500 that says how to fix it', function () {
    config(['wireguard.helper' => '/nonexistent/wgla-helper']);

    $this->getJson('/links', $this->auth)
        ->assertInternalServerError()
        ->assertJsonPath('error', 'The root helper is not installed at /nonexistent/wgla-helper. Install it with: php artisan wg:install');
});

it('reports the code it booted with in /status', function () {
    $this->host->shell->otherwise(fn () => '0');

    $this->getJson('/status', $this->auth)
        ->assertOk()
        ->assertJsonPath('app.code', Server::codeFingerprint(base_path()));
});

it('keeps .env values out of the process environment, so a reload picks up changes', function () {
    // FrankenPHP keeps the process environment across worker restarts (systemctl reload wgla),
    // and dotenv never overwrites a variable that is already set
    expect((new ReflectionProperty(Env::class, 'putenv'))->getValue())->toBeFalse();
});

it('shows only health publicly, and status and IP behind the API key', function () {
    $this->getJson('/health')->assertOk()->assertExactJson(['status' => 'ok']);

    $this->getJson('/status')->assertForbidden();
    $this->getJson('/ip')->assertForbidden();
    $this->getJson('/ip', $this->auth)->assertOk()->assertJsonPath('ipv4', '203.0.113.10');
});

it('reports itself unavailable when the root helper is not usable', function () {
    config(['wireguard.helper' => '/nonexistent/wgla-helper']);

    $this->getJson('/health')->assertStatus(503)->assertExactJson(['status' => 'unavailable']);
});

it('rejects requests without the right API key', function () {
    $this->getJson('/links')->assertForbidden();
    $this->getJson('/links', ['api-key' => 'wrong'])->assertForbidden();
});

it('locks the API instead of opening it when no API key is set', function () {
    config(['wireguard.api_key' => '']);

    $this->getJson('/links')->assertForbidden();
    $this->getJson('/links', ['api-key' => ''])->assertForbidden();
    $this->getJson('/health')->assertOk(); // public routes still work
});
it('adds, shows and removes a link\'s IPv6 address', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'address6' => 'fd12::1/64'], $this->auth)
        ->assertCreated()
        ->assertJsonPath('address6', 'fd12::1/64');
    $this->postJson('/link/wg0/peers', [], $this->auth)
        ->assertJsonPath('allowed_ips', '10.0.0.2/32, fd12::2/128');

    // Leaving it out keeps it; null removes it
    $this->patchJson('/link/wg0', ['dns' => '1.1.1.1'], $this->auth)->assertOk()->assertJsonPath('address6', 'fd12::1/64');
    $this->patchJson('/link/wg0', ['address6' => null], $this->auth)
        ->assertOk()
        ->assertJsonPath('address6', null)
        ->assertJsonPath('peers.0.allowed_ips', '10.0.0.2/32');

    $this->patchJson('/link/wg0', ['address6' => 'auto'], $this->auth)
        ->assertOk()
        ->assertJsonPath('address6', fn (string $address6) => str_starts_with($address6, 'fd') && str_ends_with($address6, '::1/64'));
    $this->patchJson('/link/wg0', ['address6' => 'fe80::1/64'], $this->auth)->assertUnprocessable();

    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();
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
