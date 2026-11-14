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
