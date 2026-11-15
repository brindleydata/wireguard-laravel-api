<?php

use App\Services\Os\LinuxDriver;
use Tests\Fakes\FakeShell;

it('hooks the helper firewall with the link as interface', function () {
    $section = (new LinuxDriver(new FakeShell, '/usr/local/sbin/wgla-helper'))
        ->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0', forward: true, nat: true);

    // wg-quick on Linux only expands %i, the interface, which is named after the link
    expect($section)->toBe(implode("\n", [
        '[Interface]',
        'Address = 10.0.0.1/24',
        'PrivateKey = KEY',
        'ListenPort = 51820',
        'PostUp = /usr/local/sbin/wgla-helper firewall-up %i %i',
        'PostDown = /usr/local/sbin/wgla-helper firewall-down %i',
    ]));
});

it('adds no hooks without forward or NAT', function () {
    $section = (new LinuxDriver(new FakeShell))->interfaceSection('10.0.0.1/24', 'KEY', 51820, 'eth0');

    expect($section)->not->toContain('PostUp')->not->toContain('PostDown');
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

it('uses the link name as the interface name without asking the helper', function () {
    $shell = new FakeShell;

    expect((new LinuxDriver($shell))->resolveInterface('wg0'))->toBe('wg0')
        ->and($shell->calls)->toBe([]);
});
