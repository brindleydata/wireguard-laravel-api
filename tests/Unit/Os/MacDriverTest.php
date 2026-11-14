<?php

use App\Services\Os\MacDriver;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;
use Tests\Support\Bash;

function macSection(bool $forward, bool $nat): string
{
    return (new MacDriver(new FakeShell))->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'en0', $forward, $nat);
}

/**
 * A hook from the macOS interface section, expanded like wg-quick on macOS: %i is the real
 * utunN, %I the link name.
 */
function macHook(string $key, bool $forward, bool $nat): string
{
    return Bash::expand(Bash::confValue(macSection($forward, $nat), $key), 'utun5', 'wg0');
}

it('writes every hook on a single line', function () {
    foreach (explode("\n", macSection(forward: true, nat: true)) as $line) {
        expect($line)->toMatch('/^(\[Interface\]|[A-Za-z]+ = \S.*)$/');
    }
});

it('loads nat then pass rules into the link anchor in PostUp', function () {
    $run = Bash::run(macHook('PostUp', forward: true, nat: true), ['pfctl' => 0]);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['calls'])->toBe([['pfctl', '-a', 'wg/wg0', '-f', '-'], ['pfctl', '-e']])
        ->and($run['stdin'][0])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\npass in on utun5 all\npass out on utun5 all\n")
        ->toBeAcceptedByPf();
});

it('fails PostUp when pf rejects the rules', function () {
    $run = Bash::run(macHook('PostUp', forward: true, nat: true), ['pfctl' => 1]);

    expect($run['exit'])->not->toBe(0, 'A rejected ruleset must fail `wg-quick up`');
});

it('flushes the link anchor in PostDown and never fails', function () {
    $run = Bash::run(macHook('PostDown', forward: true, nat: true), ['pfctl' => 1]);

    expect($run['exit'])->toBe(0)
        ->and($run['calls'])->toBe([['pfctl', '-a', 'wg/wg0', '-F', 'all']]);
});

it('adds no hooks without forward or NAT', function () {
    expect(macSection(false, false))->not->toContain('PostUp')->not->toContain('PostDown');
});

it('loads the same rules live as PostUp', function (bool $forward, bool $nat) {
    $shell = (new FakeShell)->otherwise(fn () => '');
    (new MacDriver($shell))->applyFirewall('wg0', 'utun5', '10.0.0.1/24', 'en0', $forward, $nat);

    $load = $shell->callsTo('sudo pfctl -a :anchor -f -')[0];
    $hook = Bash::run(macHook('PostUp', $forward, $nat), ['pfctl' => 0]);

    expect($load['bindings']['anchor'])->toBe('wg/wg0')
        ->and($load['input'])->toBe($hook['stdin'][0])->toBeAcceptedByPf();
})->with('firewall states');

it('flushes the anchor when applying with everything off', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');
    (new MacDriver($shell))->applyFirewall('wg0', 'utun5', '10.0.0.1/24', 'en0', false, false);

    expect(array_column($shell->calls, 'bound'))->toBe(["sudo pfctl -a 'wg/wg0' -F all"]);
});

it('resolves the interface from the wg-quick name file', function () {
    $shell = (new FakeShell)->on('sudo cat :path', fn (array $b) => match ($b['path']) {
        '/var/run/wireguard/wg0.name' => "utun7\n",
        '/var/run/wireguard/bad.name' => 'utun7; rm -rf /',
        default => throw new CommandFailed,
    });
    $driver = new MacDriver($shell);

    expect($driver->resolveInterface('wg0'))->toBe('utun7')
        ->and($driver->resolveInterface('wg1'))->toBe('wg1', 'No name file: link is down')
        ->and($driver->resolveInterface('bad'))->toBe('bad', 'Unexpected content is ignored');
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
