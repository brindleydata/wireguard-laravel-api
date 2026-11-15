<?php

use App\DTOs\PeerInfo;
use App\Services\IpAllocator;

/*
 * Address math for both families, and how peers mirror their IPv4 host number into IPv6.
 */

it('finds the network of a CIDR in either family', function (string $cidr, string $network) {
    expect(IpAllocator::networkCidr($cidr))->toBe($network);
})->with([
    ['10.0.0.7/24', '10.0.0.0/24'],
    ['10.0.0.7', '10.0.0.7/32'],
    ['fd12:3456:789a::1/64', 'fd12:3456:789a::/64'],
    ['fd12:3456:789a:1:2:3:4:5/52', 'fd12:3456:789a::/52'],
]);

it('tells whether two CIDRs overlap, never across families', function (string $a, string $b, bool $overlaps) {
    expect(IpAllocator::overlaps($a, $b))->toBe($overlaps)
        ->and(IpAllocator::overlaps($b, $a))->toBe($overlaps);
})->with([
    ['10.0.0.1/24', '10.0.0.200/25', true],
    ['10.0.0.1/24', '10.0.1.1/24', false],
    ['fd12::1/64', 'fd12::abcd/64', true],
    ['fd12::1/64', 'fd12::1/48', true],
    ['fd12::1/64', 'fd12:0:0:1::1/64', false],
    ['10.0.0.1/0', 'fd12::1/0', false],
]);

it('mirrors a peer IPv4 host number into the link IPv6 prefix', function (string $ip, string $address, string $address6, string $mirror) {
    expect(IpAllocator::mirror($ip, $address, $address6))->toBe($mirror);
})->with([
    ['10.0.0.2', '10.0.0.1/24', 'fd12:3456:789a::1/64', 'fd12:3456:789a::2'],
    ['10.0.1.5', '10.0.0.1/23', 'fd12::1/64', 'fd12::105'],
    ['10.255.255.254', '10.0.0.1/8', 'fd12::1/64', 'fd12::ff:fffe'],
    ['10.0.0.9', '10.0.0.1/24', '2001:db8:1:2::abcd/120', '2001:db8:1:2::ab09'], // /120: the ab is network
]);

it('builds server-side allowed IPs for one or both families', function () {
    expect(IpAllocator::peerAllowedIps('10.0.0.2', '10.0.0.1/24', null))->toBe('10.0.0.2/32')
        ->and(IpAllocator::peerAllowedIps('10.0.0.2', '10.0.0.1/24', 'fd12::1/64'))->toBe('10.0.0.2/32, fd12::2/128')
        ->and(IpAllocator::tunnelIp('fd12::2/128, 10.0.0.2/32'))->toBe('10.0.0.2')
        ->and(IpAllocator::tunnelIp('fd12::2/128'))->toBeNull();
});

it('skips the host number the link IPv6 address uses', function () {
    $peers = [new PeerInfo(public_key: 'k', allowed_ips: '10.0.0.2/32, fd12::2/128')];

    expect((new IpAllocator)->findAvailableIp('10.0.0.1/24', $peers))->toBe('10.0.0.3')
        ->and((new IpAllocator)->findAvailableIp('10.0.0.1/24', $peers, 'fd12::3/64'))->toBe('10.0.0.4');
});

it('generates random unique local /64 prefixes', function () {
    $prefixes = array_map(fn () => IpAllocator::randomUlaPrefix(), range(1, 20));

    foreach ($prefixes as $prefix) {
        expect($prefix)->toMatch('/^fd[0-9a-f:]+\/64$/')
            ->and(IpAllocator::networkCidr($prefix))->toBe($prefix)
            ->and(IpAllocator::overlaps($prefix, 'fd00::/8'))->toBeTrue();
    }
    expect(array_unique($prefixes))->toHaveCount(20);
});

it('tells the networks behind a peer from its tunnel addresses', function () {
    expect(IpAllocator::networksOf('10.0.0.2/32, fd12::2/128, 192.168.1.0/24, 2001:db8::/48', 'fd12::1/64'))->toBe(['192.168.1.0/24', '2001:db8::/48'])
        ->and(IpAllocator::networksOf('10.0.0.2/32, fd12::2/128', null))->toBe(['fd12::2/128'], 'Without a link prefix, a /128 is a network')
        ->and(IpAllocator::networksOf('10.0.0.2/32', null))->toBe([]);
});
