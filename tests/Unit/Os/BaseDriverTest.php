<?php

use App\Services\Os\LinuxDriver;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;

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
