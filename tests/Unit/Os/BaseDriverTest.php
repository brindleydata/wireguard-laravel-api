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
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed('wgla-helper: no config for link wg0'));
    $driver = helperDriver($shell);

    expect($driver->readConfig('wg0'))->toBeNull()
        ->and($driver->configExists('wg0'))->toBeFalse()
        ->and($driver->parseConfig('wg0'))->toBeNull()
        ->and($driver->readClientConfig('wg0', 'abc'))->toBeNull()
        ->and($driver->listConfigNames())->toBe([])
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
    'an older version' => [str_replace('VERSION=1', 'VERSION=0', file_get_contents(__DIR__.'/../../../bin/wgla-helper')), 'differs from the one this app ships (installed: v0, app: v1)'],
    'edited, same version' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper')."\n# local edit\n", '(installed: v1, app: v1)'],
]);

it('reports the helper state', function (?string $installed, bool $sudoAllowed, string $state) {
    $shell = (new FakeShell)->on('sudo -n :helper version', fn () => $sudoAllowed ? '1' : throw new CommandFailed('sudo: a password is required'));

    $status = driftDriver($shell, $installed)->helperStatus();

    expect($status['state'])->toBe($state)
        ->and($status['bundled'])->toBe('1');
})->with([
    'ok' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper'), true, 'ok'],
    'sudoers missing' => [file_get_contents(__DIR__.'/../../../bin/wgla-helper'), false, 'not-allowed'],
    'missing' => [null, true, 'missing'],
    'outdated' => ["#!/bin/bash\nVERSION=0\n", true, 'outdated'],
]);
