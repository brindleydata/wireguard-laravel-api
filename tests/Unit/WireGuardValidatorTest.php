<?php

use App\Validation\WireGuardValidator;

it('accepts DNS servers and search domains', function (string $dns) {
    expect(fn () => (new WireGuardValidator)->validateDns($dns))->not->toThrow(InvalidArgumentException::class);
})->with(['1.1.1.1', '1.1.1.1, 8.8.8.8', '2606:4700:4700::1111', '10.0.0.1,corp.example.com']);

it('rejects malformed DNS', function (string $dns) {
    expect(fn () => (new WireGuardValidator)->validateDns($dns))->toThrow(InvalidArgumentException::class);
})->with([
    'empty' => '',
    'trailing comma' => '1.1.1.1,',
    'space' => 'dns server',
    'trailing newline' => "1.1.1.1\n",
    'injected line' => "1.1.1.1\nPostUp = id",
    'shell syntax' => '1.1.1.1;id',
    'leading hyphen' => '-bad.example',
]);

it('accepts allowed IPs', function (string $allowed_ips) {
    expect(fn () => (new WireGuardValidator)->validateAllowedIps($allowed_ips))->not->toThrow(InvalidArgumentException::class);
})->with(['0.0.0.0/0', '0.0.0.0/0, ::/0', '10.0.0.2', '192.168.1.0/24,10.0.0.0/8', 'fd00::/64']);

it('rejects malformed allowed IPs', function (string $allowed_ips) {
    expect(fn () => (new WireGuardValidator)->validateAllowedIps($allowed_ips))->toThrow(InvalidArgumentException::class);
})->with([
    'empty' => '',
    'IPv4 mask too long' => '10.0.0.0/33',
    'IPv6 mask too long' => 'fd00::/129',
    'empty mask' => '10.0.0.0/',
    'non-numeric mask' => '10.0.0.0/x',
    'hostname' => 'example.com',
    'injected section' => "0.0.0.0/0\n[Interface]",
]);

it('takes a peer address as a single IP', function () {
    $validator = new WireGuardValidator;

    expect($validator->peerAddress('10.0.0.2'))->toBe('10.0.0.2')
        ->and($validator->peerAddress('10.0.0.2/32'))->toBe('10.0.0.2')
        ->and(fn () => $validator->peerAddress('10.0.0.2/24'))->toThrow(InvalidArgumentException::class);
});

it('bounds keepalive and outbound interface names', function () {
    $validator = new WireGuardValidator;

    expect(fn () => $validator->validateKeepalive(0))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateKeepalive(65535))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateOutboundInterface('eth0.100'))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateOutboundInterface('br-1a2b3c'))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateKeepalive(-1))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateKeepalive(65536))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateOutboundInterface('eth0 eth1'))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateOutboundInterface('a$(id)'))->toThrow(InvalidArgumentException::class);
});

it('takes a link IPv6 address in canonical form', function (string $given, string $address, string $canonical) {
    expect((new WireGuardValidator)->address6($given, $address))->toBe($canonical);
})->with([
    'unique local' => ['fd12:3456:789a::1/64', '10.0.0.1/24', 'fd12:3456:789a::1/64'],
    'upper case, zeros written out' => ['FD12:3456:789A:0000::0001/64', '10.0.0.1/24', 'fd12:3456:789a::1/64'],
    'global unicast' => ['2001:db8:1::1/64', '10.0.0.1/24', '2001:db8:1::1/64'],
    'a small prefix that still fits' => ['fd12::1/120', '10.0.0.1/24', 'fd12::1/120'],
]);

it('rejects IPv6 addresses a link cannot use', function (string $cidr, string $error) {
    expect(fn () => (new WireGuardValidator)->address6($cidr, '10.0.0.1/16'))->toThrow(InvalidArgumentException::class, $error);
})->with([
    'no prefix' => ['fd12::1', 'Invalid IPv6 address'],
    'IPv4' => ['10.0.0.1/24', 'Invalid IPv6 address'],
    'IPv4-mapped' => ['::ffff:10.0.0.1/96', 'Invalid IPv6 address'],
    'link-local' => ['fe80::1/64', 'neither a unique local'],
    'loopback' => ['::1/64', 'neither a unique local'],
    'multicast' => ['ff02::1/64', 'neither a unique local'],
    'the prefix itself' => ['fd12::/64', 'is the prefix itself'],
    'a /127' => ['fd12::1/127', 'prefix length'],
    'too small for the IPv4 subnet' => ['fd12::1/120', 'too small for 10.0.0.1/16'],
    'a line break' => ["fd12::1/64\nPostUp = id", 'Invalid IPv6 address'],
]);
