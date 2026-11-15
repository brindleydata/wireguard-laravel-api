<?php

use App\Services\Os\MacDriver;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;

it('hooks the helper firewall with the link name and the real utun', function () {
    $section = (new MacDriver(new FakeShell, '/usr/local/sbin/wgla-helper'))
        ->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'en0', forward: true, nat: true);

    // wg-quick on macOS expands %I to the link name and %i to the utunN it created
    expect($section)
        ->toContain('PostUp = /usr/local/sbin/wgla-helper firewall-up %I %i')
        ->toContain('PostDown = /usr/local/sbin/wgla-helper firewall-down %I');
});

it('adds no hooks without forward or NAT', function () {
    $section = (new MacDriver(new FakeShell))->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'en0');

    expect($section)->not->toContain('PostUp')->not->toContain('PostDown');
});

it('resolves the utun interface through the helper', function () {
    // The helper answers with the link name when wg-quick recorded no utunN for it
    $shell = (new FakeShell)->on('sudo -n :helper resolve :name', fn (array $b) => $b['name'] === 'wg0' ? "utun7\n" : "{$b['name']}\n");
    $driver = new MacDriver($shell);

    expect($driver->resolveInterface('wg0'))->toBe('utun7')
        ->and($driver->resolveInterface('wg1'))->toBe('wg1');
});

it('does not guess the interface when the helper cannot be asked', function () {
    // A guess (the link name) would make a running link look stopped
    $shell = (new FakeShell)->on('sudo -n :helper resolve :name', fn () => throw new CommandFailed('sudo: a password is required'));

    expect(fn () => (new MacDriver($shell))->resolveInterface('wg0'))->toThrow(CommandFailed::class, 'a password is required');
});

it('computes RAM with the page size vm_stat reports', function () {
    $shell = (new FakeShell)
        ->on('sysctl -n hw.memsize', fn () => (string) (16 * 1024 ** 3))
        ->on('vm_stat', fn () => implode("\n", [
            'Mach Virtual Memory Statistics: (page size of 16384 bytes)',
            'Pages free:                               50000.',
            'Pages active:                            300000.',
            'Pages wired down:                        100000.',
        ]));

    $ram = (new MacDriver($shell))->ram();

    // 400,000 pages x 16 KiB = 6,400,000 KiB used of 16,777,216 KiB
    expect($ram)->toBe(['total' => 16777216, 'free' => 16777216 - 6400000, 'usage' => 38]);
});
