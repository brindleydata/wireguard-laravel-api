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

it('takes any printable peer name, trimmed', function (string $name, string $stored) {
    expect((new WireGuardValidator)->peerName($name))->toBe($stored);
})->with([
    ['laptop', 'laptop'],
    ['  Ана\'s phone (#2)  ', 'Ана\'s phone (#2)'],
    [str_repeat('я', 64), str_repeat('я', 64)],
]);

it('rejects peer names that could break a config line', function (string $name) {
    expect(fn () => (new WireGuardValidator)->peerName($name))->toThrow(InvalidArgumentException::class);
})->with([
    'empty' => '   ',
    'a line break' => "laptop\nPostUp = id",
    'an escape sequence' => "laptop\e[2J",
    'too long' => str_repeat('a', 65),
    'invalid UTF-8' => "lap\xfftop",
]);

it('takes networks behind a peer as network addresses', function () {
    expect((new WireGuardValidator)->networks('192.168.1.7/24, 192.168.1.0/24,10.20.0.0/16, 2001:db8:1::5/48'))
        ->toBe(['192.168.1.0/24', '10.20.0.0/16', '2001:db8:1::/48']);
});

it('rejects networks that would hijack the server', function (string $networks) {
    expect(fn () => (new WireGuardValidator)->networks($networks))->toThrow(InvalidArgumentException::class);
})->with(['0.0.0.0/0', '::/0', '127.0.0.0/8', '169.254.0.0/16', 'fe80::/64', '224.0.0.0/8', '192.168.1.0/33', '']);

it('hands lists on the way they are written into configs', function () {
    $validator = new WireGuardValidator;

    // However they were typed: the root helper takes "a, b" and nothing else
    expect($validator->validateDns(' 1.1.1.1 ,  8.8.8.8,corp.example.com'))->toBe('1.1.1.1, 8.8.8.8, corp.example.com')
        ->and($validator->validateAllowedIps('10.0.0.0/8 ,192.168.0.0/16,  ::/0'))->toBe('10.0.0.0/8, 192.168.0.0/16, ::/0');
});

it('takes a link address as a host in a subnet of its own', function (string $given, string $address) {
    expect((new WireGuardValidator)->linkAddress($given))->toBe($address);
})->with([
    ['10.0.0.1/24', '10.0.0.1/24'],
    'a mask with a leading zero' => ['10.0.0.1/08', '10.0.0.1/8'],
    'a point-to-point /31' => ['10.0.0.0/31', '10.0.0.0/31'],
    'a single address' => ['10.0.0.1/32', '10.0.0.1/32'],
]);

it('rejects link addresses that would break routing', function (string $address, string $error) {
    expect(fn () => (new WireGuardValidator)->linkAddress($address))->toThrow(InvalidArgumentException::class, $error);
})->with([
    'every address' => ['10.0.0.1/0', 'covers every address'],
    'the network address' => ['10.0.0.0/24', 'network or broadcast address'],
    'the broadcast address' => ['10.0.0.255/24', 'network or broadcast address'],
    'the broadcast address of a /30' => ['10.0.0.3/30', 'network or broadcast address'],
    'no mask' => ['10.0.0.1', 'Invalid CIDR'],
    'IPv6' => ['fd12::1/64', 'Invalid CIDR'],
    'an octet with a leading zero' => ['10.0.0.01/24', 'Invalid IPv4 address'],
]);

it('takes where to connect to a peer as host:port', function (string $given, string $written) {
    expect((new WireGuardValidator)->remote($given))->toBe($written);
})->with([
    ['203.0.113.7:51820', '203.0.113.7:51820'],
    [' branch.example.com:51820 ', 'branch.example.com:51820'],
    ['[2001:DB8:0::7]:1', '[2001:db8::7]:1'],
]);

it('rejects a remote that is no host and port', function (string $remote) {
    expect(fn () => (new WireGuardValidator)->remote($remote))->toThrow(InvalidArgumentException::class, 'Invalid remote');
})->with(['branch.example.com', '203.0.113.7:0', '203.0.113.7:70000', '2001:db8::7:51820', '[203.0.113.7]:51820', 'branch.example.com:51820;id', "a.example.com:1\nPostUp = id", '-bad.example:1']);

it('bounds a link\'s MTU', function () {
    $validator = new WireGuardValidator;

    expect(fn () => $validator->validateMtu(576))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateMtu(1280, ipv6: true))->not->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateMtu(575))->toThrow(InvalidArgumentException::class)
        ->and(fn () => $validator->validateMtu(1279, ipv6: true))->toThrow(InvalidArgumentException::class, '1280')
        ->and(fn () => $validator->validateMtu(65536))->toThrow(InvalidArgumentException::class);
});
