<?php

use App\Services\Shell;
use App\Services\WireGuard;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/*
 * wg:backup and wg:restore through the container, with the host simulated for the current OS.
 */

beforeEach(function () {
    config(['wireguard.hostname' => 'vpn.example.test', 'wireguard.helper' => base_path('bin/wgla-helper')]);
    $shell = new FakeShell;
    $this->app->instance(Shell::class, $shell);
    $this->host = new FakeHost(PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux', $shell);

    $this->dir = sys_get_temp_dir().'/wgla_backups_'.bin2hex(random_bytes(4));
    mkdir($this->dir);
    file_put_contents("{$this->dir}/pass", "correct horse battery staple\n");

    $this->wg = app(WireGuard::class);
    $this->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $this->peer = $this->wg->addPeer('wg0');
});

afterEach(fn () => exec('rm -rf '.escapeshellarg($this->dir)));

it('writes a private backup file and refuses to overwrite one', function () {
    $file = "{$this->dir}/server.backup";

    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])
        ->expectsOutputToContain('Backed up 1 link(s) and 1 client config(s)')
        ->assertSuccessful();

    expect(sprintf('%o', fileperms($file) & 0777))->toBe('600')
        ->and(file_get_contents($file))->not->toContain($this->peer->private_key);

    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])
        ->expectsOutputToContain('already exists')
        ->assertFailed();
});

it('needs a passphrase when there is no terminal to ask in', function () {
    $this->artisan('wg:backup', ['file' => "{$this->dir}/x.backup", '--no-interaction' => true])
        ->expectsOutputToContain('No passphrase')
        ->assertFailed();
});

it('restores deleted links from a backup', function () {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();
    $key = $this->wg->getLink('wg0')->public_key;
    $this->wg->deleteLink('wg0');

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Restored wg0 (1 client config(s))')
        ->assertSuccessful();

    expect($this->wg->getLink('wg0'))->public_key->toBe($key)->up->toBeTrue()
        ->and($this->host->runtimePeers('wg0'))->toBe([$this->peer->public_key => '10.0.0.2/32'])
        ->and($this->wg->getPeerConfig('wg0', $this->peer->public_key))->toBe($this->peer->client_config);
});

it('changes nothing when a link exists and no terminal can ask about it', function () {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();
    $calls = count($this->host->shell->calls);

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain('wg0 already exists here: pass --existing=skip or --existing=replace. Nothing was restored.')
        ->assertFailed();

    $writes = array_filter(array_slice($this->host->shell->calls, $calls), fn ($call) => preg_match('/conf-write|up |down |client-write/', $call['command']));
    expect($writes)->toBe([]);
});

it('skips or replaces existing links as told', function (string $existing, string $message) {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--existing' => $existing, '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain($message)
        ->assertSuccessful();
})->with([
    'skip' => ['skip', 'Nothing to restore.'],
    'replace' => ['replace', 'Restored wg0'],
]);

it('asks in a terminal whether to skip or replace an existing link', function () {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])
        ->expectsQuestion('wg0 already exists here', 'replace')
        ->expectsConfirmation('Restore now?', 'yes')
        ->expectsOutputToContain('Restored wg0')
        ->assertSuccessful();
});

it('says so when the passphrase is wrong', function () {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();
    file_put_contents("{$this->dir}/wrong", "not the right passphrase\n");

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/wrong", '--yes' => true])
        ->expectsOutputToContain('Wrong passphrase, or the backup file is damaged.')
        ->assertFailed();
});

it('keeps a restored link that does not start, and says how to start it', function () {
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();
    $key = $this->wg->getLink('wg0')->public_key;
    $this->host->failNextStart = true;

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--existing' => 'replace', '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Restored wg0 (1 client config(s))')
        ->expectsOutputToContain('wg0 was restored but did not start: wg-quick: failed to start wg0')
        ->expectsOutputToContain('wgla link:update wg0 --up=true')
        ->assertFailed();

    expect($this->wg->getLink('wg0'))->public_key->toBe($key)->up->toBeFalse()
        ->and($this->wg->getPeerConfig('wg0', $this->peer->public_key))->toBe($this->peer->client_config);
});

it('skips a link that cannot be restored here, and one that then clashes with it', function () {
    // wg1 routes a network behind a peer; wg2 is a hand-written config
    $this->wg->createLink('wg1', '10.1.0.1/24', 51821);
    $this->wg->addPeer('wg1', networks: '192.168.60.0/24');
    $this->host->confs['wg2'] = handWrittenConf();
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])
        ->expectsOutputToContain("wg2 has settings this app doesn't manage (Table, PostUp, comments, PersistentKeepalive). It is in the backup, but a restore will skip it")
        ->assertSuccessful();

    // Here now: only a link in the network that the backed-up wg1 routes
    foreach (['wg0', 'wg1', 'wg2'] as $link) {
        $this->wg->deleteLink($link);
    }
    $this->wg->createLink('lan', '192.168.60.1/24', 51900);

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--existing' => 'skip', '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain('Restored wg0')
        ->expectsOutputToContain('Skipped: wg1, wg2')
        ->assertSuccessful();

    expect($this->wg->listLinks())->toBe(['lan', 'wg0']);
});

it('restores nothing when a link cannot be restored and nobody said to skip it', function () {
    $this->host->confs['wg2'] = handWrittenConf();
    $file = "{$this->dir}/server.backup";
    $this->artisan('wg:backup', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass"])->assertSuccessful();
    $this->wg->deleteLink('wg0');
    $this->wg->deleteLink('wg2');

    $this->artisan('wg:restore', ['file' => $file, '--passphrase-file' => "{$this->dir}/pass", '--yes' => true, '--no-interaction' => true])
        ->expectsOutputToContain('or take them out first. Nothing was restored.')
        ->assertFailed();

    expect($this->wg->listLinks())->toBe([]);
});
