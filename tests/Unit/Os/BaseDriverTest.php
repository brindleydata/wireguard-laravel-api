<?php

use App\Exceptions\HelperException;
use App\Services\Os\LinuxDriver;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;
use Tests\Support\HelperSandbox;

/*
 * The privileged half of both drivers: everything goes through the root helper.
 */

function helperDriver(FakeShell $shell): LinuxDriver
{
    return new LinuxDriver($shell, '/usr/local/sbin/wgla-helper');
}

it('runs privileged operations through the helper with sudo -n', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');
    $driver = helperDriver($shell);

    $driver->writeConfig('wg0', 'secret');
    $driver->startInterface('wg0');
    $driver->applyFirewall('wg0', 'wg0');
    $driver->removePeer('wg0', 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=');

    expect(array_column($shell->calls, 'bound'))->toBe([
        "sudo -n '/usr/local/sbin/wgla-helper' conf-write 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' up 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' firewall-up 'wg0' 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' peer-remove 'wg0' 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg='",
    ]);
});

it('hands config contents to the helper on stdin', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');
    $driver = helperDriver($shell);

    $driver->writeConfig('wg0', 'link secret');
    $driver->writeClientConfig('wg0', 'abc', 'client secret');
    $driver->addPeer('wg0', "[Peer]\n");

    expect(array_column($shell->calls, 'input'))->toBe(["link secret\n", "client secret\n", "[Peer]\n"])
        ->and(implode("\n", array_column($shell->calls, 'bound')))->not->toContain('secret');
});

it('reads a missing config as null', function () {
    // Exit status 3 is the helper's "not there"
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('wgla-helper: no config for link wg0', exitCode: 3));
    $driver = helperDriver($shell);

    expect($driver->readConfig('wg0'))->toBeNull()
        ->and($driver->configExists('wg0'))->toBeFalse()
        ->and($driver->readClientConfig('wg0', 'abc'))->toBeNull();
});

it('never reads a failure as "nothing there"', function (Closure $read) {
    // e.g. a broken sudo rule: an empty answer would make links look deleted or stopped
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('sudo: a password is required', exitCode: 1));

    expect(fn () => $read(helperDriver($shell)))->toThrow(CommandFailed::class, 'a password is required');
})->with([
    'a link config' => [fn (LinuxDriver $driver) => $driver->readConfig('wg0')],
    'a client config' => [fn (LinuxDriver $driver) => $driver->readClientConfig('wg0', 'abc')],
    'the link list' => [fn (LinuxDriver $driver) => $driver->listConfigNames()],
    'the running interfaces' => [fn (LinuxDriver $driver) => $driver->runningInterfaces()],
]);

it('never takes a delete that failed for done', function (Closure $delete) {
    // "Deleted" for a link whose config is still there would be a lie
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('rm: cannot remove: Read-only file system'));

    expect(fn () => $delete(helperDriver($shell)))->toThrow(CommandFailed::class, 'Read-only file system');
})->with([
    'a link config' => [fn (LinuxDriver $driver) => $driver->deleteConfig('wg0')],
    'a stored key' => [fn (LinuxDriver $driver) => $driver->deleteClientConfig('wg0', 'abc')],
    'the stored keys of a link' => [fn (LinuxDriver $driver) => $driver->deleteClientConfigDir('wg0')],
]);

it('tidies up firewall rules without failing', function () {
    // After a stop, whose PostDown hook has normally removed them already
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('nft: no such table'));

    helperDriver($shell)->clearFirewall('wg0');

    expect(array_column($shell->calls, 'bound'))->toBe(["sudo -n '/usr/local/sbin/wgla-helper' firewall-down 'wg0'"]);
});

it('reads no configs and no running interfaces as empty lists', function () {
    $driver = helperDriver((new FakeShell)->otherwise(fn () => ''));

    expect($driver->listConfigNames())->toBe([])
        ->and($driver->runningInterfaces())->toBe([]);
});

it('lists configs and running interfaces', function () {
    $shell = (new FakeShell)
        ->on('sudo -n :helper conf-list', fn () => "wg0\nwg1\n")
        ->on('sudo -n :helper interfaces', fn () => "wg0 wg1\n");

    expect(helperDriver($shell)->listConfigNames())->toBe(['wg0', 'wg1'])
        ->and(helperDriver($shell)->runningInterfaces())->toBe(['wg0', 'wg1']);
});

it('passes helper failures on with their message', function () {
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('sudo: a password is required'));

    expect(fn () => helperDriver($shell)->startInterface('wg0'))->toThrow(CommandFailed::class, 'sudo: a password is required');
});

// ─── Helper drift ───────────────────────────────────────────────────

/**
 * A driver whose "installed" helper is a temp file with the given content (null: missing),
 * compared against the real bundled bin/wgla-helper.
 */
function driftDriver(FakeShell $shell, ?string $installed): LinuxDriver
{
    $path = sys_get_temp_dir().'/wgla_installed_'.bin2hex(random_bytes(4));
    if ($installed !== null) {
        file_put_contents($path, $installed);
        register_shutdown_function(fn () => @unlink($path));
    }

    return new LinuxDriver($shell, $path, HelperSandbox::path());
}

it('uses an installed helper identical to the bundled one', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');

    driftDriver($shell, file_get_contents(HelperSandbox::path()))->startInterface('wg0');

    expect($shell->calls)->toHaveCount(1);
});

it('refuses a missing or different helper before running anything', function (?string $installed, string $message) {
    $shell = (new FakeShell)->otherwise(fn () => '');
    $driver = driftDriver($shell, $installed);

    expect(fn () => $driver->startInterface('wg0'))->toThrow(HelperException::class, $message)
        // Reads too: a stale helper must not look like "link not found"
        ->and(fn () => $driver->readConfig('wg0'))->toThrow(HelperException::class)
        ->and($shell->calls)->toBe([]);
})->with([
    'missing' => [null, 'The root helper is not installed at'],
    'an older version' => [str_replace('VERSION='.helperVersion(), 'VERSION=0', file_get_contents(__DIR__.'/../../../bin/wgla-helper')), 'differs from the one this app ships (installed: v0, app: v'.helperVersion().')'],
    'edited, same version' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper')."\n# local edit\n", '(installed: v'.helperVersion().', app: v'.helperVersion().')'],
]);

it('reports the helper state', function (?string $installed, bool $sudoAllowed, string $state) {
    $shell = (new FakeShell)->on('sudo -n :helper version', fn () => $sudoAllowed ? '1' : throw new CommandFailed('sudo: a password is required'));

    $status = driftDriver($shell, $installed)->helperStatus();

    expect($status['state'])->toBe($state)
        ->and($status['bundled'])->toBe(helperVersion());
})->with([
    'ok' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper'), true, 'ok'],
    'sudoers missing' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper'), false, 'not-allowed'],
    'missing' => [null, true, 'missing'],
    'outdated' => ["#!/bin/bash\nVERSION=0\n", true, 'outdated'],
]);

// ─── Public IP ──────────────────────────────────────────────────────

it('only reports a public IP of the asked family', function (string $flag, string $answer, ?string $expected) {
    $shell = (new FakeShell)->on("curl {$flag} -s --max-time 5 :url", fn () => $answer);
    $driver = helperDriver($shell);

    expect($flag === '-4' ? $driver->publicIpv4('http://ip.test') : $driver->publicIpv6('http://ip.test'))->toBe($expected);
})->with([
    'IPv4' => ['-4', '203.0.113.10', '203.0.113.10'],
    'IPv6' => ['-6', '2001:db8::7', '2001:db8::7'],
    // No real IPv6: DNS gave an IPv4-mapped address (::ffff:…), the service saw IPv4
    'IPv4 when asked for IPv6' => ['-6', '203.0.113.10', null],
    'IPv6 when asked for IPv4' => ['-4', '2001:db8::7', null],
    'an error page' => ['-4', '<html>502 Bad Gateway</html>', null],
]);

it('hooks the helper firewall for a link with destinations too: they are rules that come and go with it', function () {
    $driver = helperDriver(new FakeShell);

    expect($driver->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0', scoped: true))
        ->toContain('PostUp = /usr/local/sbin/wgla-helper firewall-up %i %i', 'PostDown = /usr/local/sbin/wgla-helper firewall-down %i')
        ->and($driver->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0'))->not->toContain('PostUp');
});

it('adopts a config through the helper, which keeps the one it replaces', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');
    $driver = helperDriver($shell);

    $driver->checkConfig('wg0', 'new config');
    $driver->adoptConfig('wg0', 'new config');
    $driver->undoAdoptedConfig('wg0');
    $driver->confirmAdoptedConfig('wg0');

    // The new one on stdin; the old one is never the app's to hand in
    expect(array_column($shell->calls, 'bound'))->toBe([
        "sudo -n '/usr/local/sbin/wgla-helper' conf-check 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' conf-adopt 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' conf-adopt-undo 'wg0'",
        "sudo -n '/usr/local/sbin/wgla-helper' conf-adopt-done 'wg0'",
    ])->and(array_column($shell->calls, 'input'))->toBe(["new config\n", "new config\n", null, null]);

    // Tidying up after a link that runs with its new config never fails the adoption
    $shell->otherwise(fn () => throw new CommandFailed('rm: Read-only file system'));
    $driver->confirmAdoptedConfig('wg0');
    expect(fn () => $driver->undoAdoptedConfig('wg0'))->toThrow(CommandFailed::class)
        ->and(fn () => $driver->checkConfig('wg0', 'x'))->toThrow(CommandFailed::class);
});

it('reads whose keys a link\'s client directory has, and which the helper took over', function () {
    $shell = (new FakeShell)
        ->on('sudo -n :helper client-keys :link', fn () => "stored AAA=\nlegacy BBB=\nlegacy BBB=\nlegacy CCC=\nsomething else\n")
        ->on('sudo -n :helper client-import :link', fn (array $b) => $b['link'] === 'wg0' ? "BBB=\nCCC=" : '');
    $driver = helperDriver($shell);

    expect($driver->clientKeys('wg0'))->toBe(['stored' => ['AAA='], 'legacy' => ['BBB=', 'CCC=']])
        ->and($driver->importLegacyClientKeys('wg0'))->toBe(['BBB=', 'CCC='])
        ->and($driver->importLegacyClientKeys('wg1'))->toBe([]);

    $shell->on('sudo -n :helper client-keys :link', fn () => '');
    expect($driver->clientKeys('wg0'))->toBe(['stored' => [], 'legacy' => []]);
});
