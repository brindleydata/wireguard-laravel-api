<?php

use App\Http\Middleware\AuthenticateByApiKey;
use App\Services\KeyManager;
use App\Services\Server;
use App\Services\Shell;
use App\Services\WireGuard;
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

it('refuses an address for a while once it sent too many wrong keys', function () {
    $from = fn (string $ip) => $this->withServerVariables(['REMOTE_ADDR' => $ip]);
    for ($i = 0; $i < AuthenticateByApiKey::ATTEMPTS; $i++) {
        $from('198.51.100.7')->getJson('/links', ['api-key' => "guess {$i}"])->assertForbidden();
    }

    // The key can't be guessed at speed: not even the right one gets through from there now
    $from('198.51.100.7')->getJson('/links', ['api-key' => 'guess'])->assertStatus(429)->assertHeader('Retry-After')
        ->assertJsonPath('error', fn (string $error) => str_contains($error, 'Too many requests with a wrong API key'));
    $from('198.51.100.7')->getJson('/links', $this->auth)->assertStatus(429);

    // Other addresses, and the public health check, as before
    $from('198.51.100.8')->getJson('/links', $this->auth)->assertOk();
    $from('198.51.100.7')->getJson('/health')->assertOk();
});

it('counts the clients of a proxy on this host each on their own', function () {
    // As behind nginx or Caddy with --tls=http: every request comes from 127.0.0.1
    for ($i = 0; $i < AuthenticateByApiKey::ATTEMPTS; $i++) {
        $this->getJson('/links', ['api-key' => 'guess', 'X-Forwarded-For' => '203.0.113.66'])->assertForbidden();
    }

    $this->getJson('/links', ['api-key' => 'guess', 'X-Forwarded-For' => '203.0.113.66'])->assertStatus(429);
    $this->getJson('/links', [...$this->auth, 'X-Forwarded-For' => '203.0.113.67'])->assertOk();
});

it('keeps preshared keys out of listings: they are in the client config', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $peer = $this->postJson('/link/wg0/peers', [], $this->auth)->assertCreated()->json();
    $safe = KeyManager::pubkeyToSafe($peer['public_key']);

    foreach (['/link/wg0', '/link/wg0/peers', "/link/wg0/peer/{$safe}"] as $route) {
        expect($this->getJson($route, $this->auth)->assertOk()->getContent())->not->toContain('preshared_key')->not->toContain('PresharedKey');
    }
    expect($this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->json('config'))->toMatch('/^PresharedKey = \S+$/m')
        ->and($peer['client_config'])->toMatch('/^PresharedKey = \S+$/m');
});

it('takes a link\'s inbound and route settings', function () {
    $this->host->policy['allow_default_route'] = true;

    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'forward' => true, 'inbound' => true, 'allow_default_route' => true], $this->auth)
        ->assertCreated()->assertJsonPath('inbound', true)->assertJsonPath('allow_default_route', true)->assertJsonPath('allow_own_networks', false);
    $this->patchJson('/link/wg0', ['inbound' => false], $this->auth)->assertOk()->assertJsonPath('inbound', false);

    // What the server's policy doesn't allow, a link can't either
    $this->patchJson('/link/wg0', ['allow_own_networks' => true], $this->auth)->assertStatus(409)
        ->assertJsonPath('error', fn (string $error) => str_contains($error, 'wg:install --allow-own-networks=true'));
});

it('takes keys of their own, gives a link new keys, and keeps where its clients connect', function () {
    $keys = new KeyManager;
    $link_key = $keys->genkey();
    $device = $keys->pubkey($keys->genkey());

    $link = $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'private_key' => $link_key, 'endpoint' => 'vpn.example.org:443'], $this->auth)
        ->assertCreated()->assertJsonPath('public_key', $keys->pubkey($link_key))->assertJsonPath('endpoint', 'vpn.example.org:443')->assertJsonMissingPath('private_key')->json();
    $peer = $this->postJson('/link/wg0/peers', ['public_key' => $device, 'dns' => '1.1.1.1', 'enabled' => false], $this->auth)
        ->assertCreated()->assertJsonPath('enabled', false)->assertJsonPath('client.dns', '1.1.1.1')->assertJsonMissingPath('private_key')->json();
    $safe = KeyManager::pubkeyToSafe($device);

    // A config without the PrivateKey line (the device has it), and no QR code of that
    expect($this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->assertOk()->json('config'))->toContain('Endpoint = vpn.example.org:443')->not->toContain('PrivateKey');
    $this->getJson("/link/wg0/peer/{$safe}/qr", $this->auth)->assertUnprocessable()->assertJsonPath('error', fn (string $error) => str_contains($error, "isn't stored here"));

    $rekeyed = $this->postJson('/link/wg0/rekey', [], $this->auth)->assertOk()->json();
    expect($rekeyed['public_key'])->not->toBe($link['public_key'])
        ->and($this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->json('config'))->toContain("PublicKey = {$rekeyed['public_key']}");
    $this->patchJson('/link/wg0', ['endpoint' => null], $this->auth)->assertOk()->assertJsonPath('endpoint', 'vpn.example.test');
    expect($peer['public_key'])->toBe($device);
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
        ->assertJsonPath('error', fn (string $error) => str_contains($error, "has settings this app doesn't manage (Table, PostUp, comments, PersistentKeepalive)"));
    $this->patchJson('/link/office', ['dns' => '1.1.1.1'], $this->auth)->assertConflict();
    expect($this->host->conf('office'))->toContain('Table = off', 'PersistentKeepalive = 15');

    $this->deleteJson('/link/office', [], $this->auth)->assertOk();
});

it('shows an interface that runs without a config, and refuses to change or delete it with a 409', function () {
    $this->host->addUnmanagedInterface('wg9');

    $this->getJson('/link/wg9', $this->auth)->assertOk()->assertJsonPath('up', true)->assertJsonPath('listen_port', 40000);
    $this->postJson('/link/wg9/peers', [], $this->auth)
        ->assertConflict()
        ->assertJsonPath('error', fn (string $error) => str_starts_with($error, 'wg9 is a running WireGuard interface without a config here'));
    $this->patchJson('/link/wg9', ['up' => false], $this->auth)->assertConflict();
    $this->deleteJson('/link/wg9', [], $this->auth)->assertConflict();

    expect(array_keys($this->host->interfaces))->toBe(['wg9'])
        ->and($this->host->files())->toBe([]);
});

it('answers a delete the host did not carry out with a 500, not with "deleted"', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    app(Shell::class)->on('sudo -n :helper conf-delete :name', fn () => throw new CommandFailed('rm: cannot remove: Read-only file system'));

    $this->deleteJson('/link/wg0', [], $this->auth)
        ->assertStatus(500)
        ->assertJsonPath('error', fn (string $error) => str_contains($error, 'Read-only file system'));
    $this->getJson('/link/wg0', $this->auth)->assertOk()->assertJsonPath('up', false);
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

it('answers every error as {"error": …}, whoever refuses the request', function () {
    $this->getJson('/links')->assertForbidden()->assertExactJson(['error' => 'Access denied.']);
    $this->putJson('/links', [], $this->auth)->assertStatus(405)->assertJsonStructure(['error'])->assertJsonMissingPath('message');
    $this->getJson('/nope', $this->auth)->assertNotFound()->assertJsonStructure(['error']);

    // A request that fails its field rules also says which fields
    $this->postJson('/link', ['name' => 'wg0', 'port' => 'high'], $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', 'The ip field is required.')
        ->assertJsonPath('errors.port.0', 'The port field must be an integer.')
        ->assertJsonMissingPath('message');
});

it('has no public route but /health', function () {
    $public = collect(app('router')->getRoutes())
        ->reject(fn ($route) => in_array(AuthenticateByApiKey::class, $route->gatherMiddleware(), true))
        ->map(fn ($route) => $route->uri())
        ->values()->all();

    // The framework's own would be /storage/{path}, for a disk this app doesn't serve
    expect($public)->toBe(['health']);
});

it('asks the root helper about health once in a while, not for every request', function () {
    $asked = fn () => count($this->host->shell->callsTo('sudo -n :helper version'));
    // As Octane serves each request: with a new controller, and new services made for it
    $request = function () {
        foreach (app('router')->getRoutes() as $route) {
            $route->flushController();
        }
        app()->forgetInstance(Server::class);

        return $this->getJson('/health');
    };

    $request()->assertOk();
    $request()->assertOk();
    $request()->assertOk();
    expect($asked())->toBe(1);

    // /status is behind the API key and always asks
    $this->host->shell->otherwise(fn () => '0');
    $this->getJson('/status', $this->auth)->assertOk();
    expect($asked())->toBe(2);
});

it('never keeps an unhealthy answer', function () {
    $allowed = false;
    $this->host->shell->on('sudo -n :helper version', function () use (&$allowed) {
        return $allowed ? '1' : throw new CommandFailed('sudo: a password is required');
    });

    $this->getJson('/health')->assertStatus(503);
    $allowed = true; // the sudo rule is fixed
    $this->getJson('/health')->assertOk();
});

it('shows and changes a peer\'s own client settings, keepalive included', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $safe = KeyManager::pubkeyToSafe($this->postJson('/link/wg0/peers', [], $this->auth)
        ->assertJsonPath('client', ['dns' => null, 'keepalive' => null, 'allowed_ips' => null])
        ->json('public_key'));

    $this->patchJson("/link/wg0/peer/{$safe}", ['dns' => '1.1.1.1', 'keepalive' => 0], $this->auth)
        ->assertOk()
        ->assertJsonPath('client', ['dns' => '1.1.1.1', 'keepalive' => 0, 'allowed_ips' => null])
        ->assertJsonPath('client_config', fn (string $config) => str_contains($config, 'PersistentKeepalive = 0'));
    $this->getJson('/link/wg0/peers', $this->auth)->assertJsonPath('0.client.keepalive', 0);

    $this->patchJson("/link/wg0/peer/{$safe}", ['keepalive' => null], $this->auth)
        ->assertJsonPath('client', ['dns' => '1.1.1.1', 'keepalive' => null, 'allowed_ips' => null]);
    $this->patchJson("/link/wg0/peer/{$safe}", ['keepalive' => 70000], $this->auth)->assertUnprocessable();
});

it('moves a link to another subnet only with move_peers', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $this->postJson('/link/wg0/peers', ['ip' => '10.0.0.9'], $this->auth)->assertCreated();

    $this->patchJson('/link/wg0', ['address' => '10.1.0.1/24'], $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', fn (string $error) => str_contains($error, 'pass move_peers (--move-peers)'));
    $this->patchJson('/link/wg0', ['address' => '10.1.0.1/24', 'move_peers' => true], $this->auth)
        ->assertOk()
        ->assertJsonPath('address', '10.1.0.1/24')
        ->assertJsonPath('peers.0.allowed_ips', '10.1.0.9/32');
});

it('answers 422 for a QR code of a config that is too long for one', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $safe = KeyManager::pubkeyToSafe($this->postJson('/link/wg0/peers', [], $this->auth)->json('public_key'));
    $routes = implode(', ', array_map(fn (int $i) => "10.{$i}.0.0/16", range(1, 250)));
    $this->patchJson("/link/wg0/peer/{$safe}", ['allowed_ips' => $routes], $this->auth)->assertOk();

    $this->getJson("/link/wg0/peer/{$safe}/qr", $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', 'This client config is too long for a QR code.');
    $this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->assertOk();
});

it('shows one peer, and a link\'s own settings', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'dns' => '9.9.9.9', 'mtu' => 1380, 'forward' => true], $this->auth)
        ->assertCreated()
        ->assertJsonPath('mtu', 1380)
        ->assertJsonPath('client', ['dns' => '9.9.9.9', 'keepalive' => null, 'allowed_ips' => null])
        ->assertJsonPath('firewall', 'ok');
    $peer = $this->postJson('/link/wg0/peers', ['name' => 'branch', 'remote' => 'branch.example.com:51820'], $this->auth)
        ->assertCreated()
        ->assertJsonPath('remote', 'branch.example.com:51820')
        ->assertJsonPath('client_config', fn (string $config) => str_contains($config, "MTU = 1380\n"))
        ->json();
    $safe = KeyManager::pubkeyToSafe($peer['public_key']);

    $this->getJson("/link/wg0/peer/{$safe}", $this->auth)
        ->assertOk()
        ->assertJsonPath('name', 'branch')
        ->assertJsonPath('remote', 'branch.example.com:51820')
        ->assertJsonPath('connected', false)
        ->assertJsonMissingPath('private_key');
    $this->getJson('/link/wg0/peer/'.str_repeat('A', 43), $this->auth)->assertNotFound();
    $this->getJson("/link/wg0/peer/{$safe}")->assertForbidden();

    // null takes the MTU and the remote out again
    $this->patchJson('/link/wg0', ['mtu' => null], $this->auth)->assertOk()->assertJsonPath('mtu', null);
    $this->patchJson("/link/wg0/peer/{$safe}", ['remote' => null], $this->auth)->assertOk()->assertJsonPath('remote', null);
    $this->patchJson("/link/wg0/peer/{$safe}", ['remote' => 'no port'], $this->auth)->assertUnprocessable();
    $this->patchJson('/link/wg0', ['mtu' => 100], $this->auth)->assertUnprocessable();
});

it('gives a peer new keys under a new public key', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $old = $this->postJson('/link/wg0/peers', ['name' => 'laptop'], $this->auth)->json();
    $safe = KeyManager::pubkeyToSafe($old['public_key']);

    $new = $this->postJson("/link/wg0/peer/{$safe}/rekey", [], $this->auth)
        ->assertOk()
        ->assertJsonPath('name', 'laptop')
        ->assertJsonPath('allowed_ips', '10.0.0.2/32')
        ->json();

    expect($new['public_key'])->not->toBe($old['public_key'])
        ->and($new['client_config'])->toContain("PrivateKey = {$new['private_key']}\n")->not->toContain($old['private_key']);
    $this->getJson("/link/wg0/peer/{$safe}/config", $this->auth)->assertNotFound();
    $this->getJson('/link/wg0/peer/'.KeyManager::pubkeyToSafe($new['public_key']).'/config', $this->auth)->assertOk()->assertJsonPath('config', $new['client_config']);
    $this->postJson("/link/wg0/peer/{$safe}/rekey", [], $this->auth)->assertNotFound();
});

it('reports missing firewall rules and puts them back on request', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820, 'nat' => true], $this->auth)->assertCreated();
    unset($this->host->firewall['wg0']); // another tool flushed the ruleset

    $this->getJson('/link/wg0', $this->auth)->assertOk()->assertJsonPath('firewall', 'missing');
    $this->postJson('/link/wg0/repair', [], $this->auth)->assertOk()->assertJsonPath('firewall', 'ok');
    $this->postJson('/link/nope/repair', [], $this->auth)->assertNotFound();

    expect($this->host->firewall['wg0'])->toBe(['forward' => false, 'nat' => true]);
});

it('refuses networks that cover an address of the server with a 422', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();

    $this->postJson('/link/wg0/peers', ['networks' => '192.0.2.0/24'], $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', fn (string $error) => str_starts_with($error, '192.0.2.0/24 covers 192.0.2.10, an address this server uses itself'));
});

it('refuses a field it does not know instead of ignoring it', function (string $method, string $uri, array $body, string $error) {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    $safe = KeyManager::pubkeyToSafe($this->postJson('/link/wg0/peers', [], $this->auth)->json('public_key'));
    $before = $this->host->conf('wg0');

    // A misspelled field used to get a 200 that had changed nothing
    $this->json($method, str_replace('{peer}', $safe, $uri), $body, $this->auth)
        ->assertUnprocessable()
        ->assertJsonPath('error', fn (string $message) => str_starts_with($message, $error));

    expect($this->host->conf('wg0'))->toBe($before)
        ->and(app(WireGuard::class)->listLinks())->toBe(['wg0']);
})->with([
    'creating a link' => ['POST', '/link', ['name' => 'wg1', 'ip' => '10.1.0.1/24', 'adress6' => 'auto'], 'Unknown field: adress6. Known: name, ip, address6,'],
    'changing a link' => ['PATCH', '/link/wg0', ['forwrad' => true, 'allowedips' => '10.0.0.0/8'], 'Unknown fields: forwrad, allowedips. Known: address,'],
    'adding a peer' => ['POST', '/link/wg0/peers', ['name' => 'x', 'network' => '192.168.1.0/24'], 'Unknown field: network. Known: ip, name, networks, remote, public_key,'],
    'changing a peer' => ['PATCH', '/link/wg0/peer/{peer}', ['enable' => false], 'Unknown field: enable. Known: ip,'],
]);

it('lists the host\'s interfaces, for a link\'s ifout', function () {
    $this->postJson('/link', ['name' => 'wg0', 'ip' => '10.0.0.1/24', 'port' => 51820], $this->auth)->assertCreated();
    [$uplink, $loopback] = PHP_OS_FAMILY === 'Darwin' ? ['en0', 'lo0'] : ['eth0', 'lo'];

    $this->getJson('/interfaces', $this->auth)
        ->assertOk()
        ->assertJsonPath('default', $uplink)
        ->assertJsonPath('interfaces', [$loopback, $uplink, $this->host->interfaceOf('wg0')]);
    $this->getJson('/interfaces')->assertForbidden();
});
