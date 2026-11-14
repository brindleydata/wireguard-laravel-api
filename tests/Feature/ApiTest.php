<?php

use App\Services\KeyManager;
use App\Services\Server;
use App\Services\Shell;
use Illuminate\Support\Env;
use Tests\Fakes\CommandFailed;
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

it('names, disables and routes networks to peers', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $peer = $this->postJson('/link/wg0/peers', ['name' => 'branch', 'networks' => '192.168.1.0/24'], $this->auth)
        ->assertCreated()
        ->assertJsonPath('name', 'branch')
        ->assertJsonPath('enabled', true)
        ->assertJsonPath('networks', '192.168.1.0/24')
        ->assertJsonPath('allowed_ips', '10.0.0.2/32, 192.168.1.0/24')
        ->json();
    $safe = KeyManager::pubkeyToSafe($peer['public_key']);

    $this->patchJson("/link/wg0/peer/{$safe}", ['enabled' => false, 'name' => 'branch office'], $this->auth)
        ->assertOk()
        ->assertJsonPath('enabled', false)
        ->assertJsonPath('name', 'branch office');
    $this->getJson('/link/wg0/peers', $this->auth)
        ->assertJsonPath('0.enabled', false)
        ->assertJsonPath('0.connected', null);

    // Leaving fields out keeps them; null removes them
    $this->patchJson("/link/wg0/peer/{$safe}", ['enabled' => true], $this->auth)
        ->assertJsonPath('name', 'branch office')
        ->assertJsonPath('networks', '192.168.1.0/24');
    $this->patchJson("/link/wg0/peer/{$safe}", ['name' => null, 'networks' => null], $this->auth)
        ->assertJsonPath('name', null)
        ->assertJsonPath('networks', null)
        ->assertJsonPath('allowed_ips', '10.0.0.2/32');

    $this->patchJson("/link/wg0/peer/{$safe}", ['networks' => '0.0.0.0/0'], $this->auth)->assertUnprocessable();
    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();
});

it('takes a link\'s or peer\'s own client setting out with null', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'dns' => '9.9.9.9 ,1.1.1.1', 'keepalive' => 15], $this->auth)->assertCreated();
    $safe = KeyManager::pubkeyToSafe($this->postJson('/link/wg0/peers', [], $this->auth)->json('public_key'));
    $config = fn () => $this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->json('config');
    expect($config())->toContain("DNS = 9.9.9.9, 1.1.1.1\n", 'PersistentKeepalive = 15');

    // Leaving a field out keeps it; null goes back to the default
    $this->patchJson('/link/wg0', ['forward' => true], $this->auth)->assertOk();
    expect($config())->toContain("DNS = 9.9.9.9, 1.1.1.1\n");
    $this->patchJson('/link/wg0', ['dns' => null, 'keepalive' => null], $this->auth)->assertOk();
    expect($config())->toContain("DNS = 8.8.8.8\n", 'PersistentKeepalive = 25');

    $this->patchJson("/link/wg0/peer/{$safe}", ['dns' => '1.1.1.1', 'allowed_ips' => '10.0.0.0/24'], $this->auth)->assertOk();
    $this->patchJson("/link/wg0/peer/{$safe}", ['name' => 'laptop'], $this->auth)->assertOk();
    expect($config())->toContain("DNS = 1.1.1.1\n", "AllowedIPs = 10.0.0.0/24\n");
    $this->patchJson("/link/wg0/peer/{$safe}", ['dns' => null, 'allowed_ips' => null], $this->auth)
        ->assertOk()
        ->assertJsonPath('name', 'laptop');
    expect($config())->toContain("DNS = 8.8.8.8\n", "AllowedIPs = 0.0.0.0/0\n");

    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();
});

it('answers 500, not "no links", when the host cannot be asked', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $this->host->shell->on('sudo -n :helper interfaces', fn () => throw new CommandFailed('sudo: a password is required'));

    $this->getJson('/links', $this->auth)->assertInternalServerError()->assertJsonPath('error', 'sudo: a password is required');
    $this->getJson('/link/wg0', $this->auth)->assertInternalServerError();
    $this->postJson('/link/wg0/peers', [], $this->auth)->assertInternalServerError();

    // What can't exist is still a plain 404
    $this->getJson('/link/no.such.link', $this->auth)->assertNotFound();
});

it('refuses to change a hand-written config with a 409', function () {
    $this->host->confs['office'] = handWrittenConf();

    $this->getJson('/link/office', $this->auth)->assertOk()->assertJsonPath('address', '10.7.0.1/24');
    $this->postJson('/link/office/peers', [], $this->auth)
        ->assertConflict()
        ->assertJsonPath('error', fn (string $error) => str_contains($error, "has settings this app doesn't manage (MTU, PostUp, comments, Endpoint, PersistentKeepalive)"));
    $this->patchJson('/link/office', ['dns' => '1.1.1.1'], $this->auth)->assertConflict();
    expect($this->host->conf('office'))->toContain('MTU = 1380', 'Endpoint = branch.example.com:51820');

    $this->deleteJson('/link/office', [], $this->auth)->assertOk();
});

it('serves a peer config as a QR code', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $safe = KeyManager::pubkeyToSafe($this->postJson('/link/wg0/peers', [], $this->auth)->json('public_key'));

    $response = $this->get("/link/wg0/peer/{$safe}/qr", $this->auth)->assertOk();

    expect($response->headers->get('Content-Type'))->toStartWith('image/svg+xml')
        ->and($response->headers->get('Cache-Control'))->toContain('no-store')
        ->and($response->getContent())->toContain('<svg');
    $this->get('/link/wg0/peer/'.str_repeat('A', 43).'/qr', $this->auth)->assertNotFound();
    $this->get("/link/wg0/peer/{$safe}/qr")->assertForbidden();
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

    // A change the link doesn't start with: undone, and reported
    $this->host->failNextStart = true;
    $this->patchJson('/link/wg0', ['port' => 51999], $this->auth)
        ->assertInternalServerError()
        ->assertJsonPath('error', 'The change to link wg0 could not be applied and was undone: wg-quick: failed to start wg0');
    $this->getJson('/link/wg0', $this->auth)->assertJsonPath('up', true)->assertJsonPath('listen_port', 51820);

    // An address no interface can have, and a list typed loosely (stored as "a, b")
    $this->patchJson('/link/wg0', ['address' => '10.0.0.0/24'], $this->auth)->assertUnprocessable();
    $this->patchJson('/link/wg0', ['allowed_ips' => '10.0.0.0/8 ,192.168.0.0/16'], $this->auth)->assertOk();
    expect($this->host->conf('wg0'))->toContain("# allowed_ips = 10.0.0.0/8, 192.168.0.0/16\n");
    $this->postJson('/link', $link, $this->auth)
        ->assertConflict()
        ->assertJsonPath('error', 'Link already exists: wg0');

    $this->deleteJson('/link/wg1', [], $this->auth)
        ->assertNotFound()
        ->assertJsonPath('error', 'Link does not exist: wg1');

    $this->deleteJson('/link/wg0', [], $this->auth)->assertOk();
});
