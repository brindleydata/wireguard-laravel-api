<?php

use App\Services\Os\LinuxDriver;
use Tests\Fakes\FakeShell;
use Tests\Support\Bash;

/**
 * A PostUp/PostDown hook from the Linux interface section, with %i expanded like wg-quick does.
 */
function linuxHook(string $key, bool $forward, bool $nat): string
{
    $section = (new LinuxDriver(new FakeShell))->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0', $forward, $nat);

    return Bash::expand(Bash::confValue($section, $key), 'wg0');
}

it('builds the link table in PostUp', function () {
    $run = Bash::run(linuxHook('PostUp', forward: true, nat: true), ['nft' => 0]);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['calls'])->toBe([
            ['nft', 'add', 'table', 'inet', 'wg_wg0'],
            ['nft', 'add', 'chain', 'inet', 'wg_wg0', 'forward', '{ type filter hook forward priority 0; }'],
            ['nft', 'add', 'rule', 'inet', 'wg_wg0', 'forward', 'iifname', 'wg0', 'accept'],
            ['nft', 'add', 'rule', 'inet', 'wg_wg0', 'forward', 'oifname', 'wg0', 'accept'],
            ['nft', 'add', 'chain', 'inet', 'wg_wg0', 'postrouting', '{ type nat hook postrouting priority 100; }'],
            ['nft', 'add', 'rule', 'inet', 'wg_wg0', 'postrouting', 'oifname', 'eth0', 'masquerade'],
        ]);
});

it('drops the table in PostDown and tolerates it being gone', function () {
    $run = Bash::run(linuxHook('PostDown', forward: true, nat: true), ['nft' => 1]);

    expect($run['exit'])->toBe(0, 'A failing PostDown would make `wg-quick down` fail')
        ->and($run['calls'])->toBe([['nft', 'delete', 'table', 'inet', 'wg_wg0']]);
});

it('adds no hooks without forward or NAT', function () {
    $section = (new LinuxDriver(new FakeShell))->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0');

    expect($section)->not->toContain('PostUp')->not->toContain('PostDown');
});

it('applies the same rules live as PostUp', function (bool $forward, bool $nat) {
    $shell = (new FakeShell)->otherwise(fn () => '');
    (new LinuxDriver($shell))->applyFirewall('wg0', 'wg0', '10.0.0.1/24', 'eth0', $forward, $nat);

    $applied = Bash::run(implode("\n", array_column($shell->calls, 'bound')), ['nft' => 0]);
    $hook = Bash::run(linuxHook('PostUp', $forward, $nat), ['nft' => 0]);

    expect($applied['exit'])->toBe(0, $applied['stderr'])
        ->and($applied['calls'][0])->toBe(['nft', 'delete', 'table', 'inet', 'wg_wg0'], 'Starts from a clean table')
        ->and(array_slice($applied['calls'], 1))->toBe($hook['calls']);
})->with('firewall states');

it('only drops the table when applying with everything off', function () {
    $shell = (new FakeShell)->otherwise(fn () => '');
    (new LinuxDriver($shell))->applyFirewall('wg0', 'wg0', '10.0.0.1/24', 'eth0', false, false);

    expect(array_column($shell->calls, 'bound'))->toBe(["sudo nft delete table inet 'wg_wg0'"]);
});

it('lists container, bridge and VLAN interface names', function () {
    $shell = (new FakeShell)->on('ip link show', fn () => implode("\n", [
        '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000',
        '    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00',
        '2: eth0@if7: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default',
        '    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0',
        '3: br-1a2b3c: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN mode DEFAULT group default',
        '4: eth0.100@eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP mode DEFAULT group default',
        '5: wg-office: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 qdisc noqueue state UNKNOWN mode DEFAULT group default',
    ]));

    expect((new LinuxDriver($shell))->networkInterfaces())
        ->toBe(['lo', 'eth0', 'br-1a2b3c', 'eth0.100', 'wg-office']);
});

it('uses the link name as the interface name', function () {
    $shell = new FakeShell;

    expect((new LinuxDriver($shell))->resolveInterface('wg0'))->toBe('wg0')
        ->and($shell->calls)->toBe([]);
});
