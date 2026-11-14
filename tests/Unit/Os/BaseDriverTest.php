<?php

use App\Services\Os\LinuxDriver;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;

const INSTALL_FILE = 'sudo mkdir -p :dir && sudo cp :tmp :path && sudo chmod 600 :path';

it('stages a config as a private file under /tmp', function () {
    $staged = null;
    $shell = (new FakeShell)->on(INSTALL_FILE, function (array $b) use (&$staged) {
        clearstatcache();
        $staged = [
            'bindings' => $b,
            'mode' => sprintf('%04o', fileperms($b['tmp']) & 0777),
            'content' => file_get_contents($b['tmp']),
        ];

        return '';
    });

    (new LinuxDriver($shell))->writeConfig('wg0', 'secret');

    // Literal /tmp: sudoers allows `cp /tmp/* ...`, and tempnam() would give /private/tmp on macOS
    expect($staged['bindings'])->toMatchArray(['dir' => '/etc/wireguard', 'path' => '/etc/wireguard/wg0.conf'])
        ->and($staged['bindings']['tmp'])->toMatch('#^/tmp/wgla_[0-9a-f]{16}$#')->not->toBeFile()
        ->and($staged['mode'])->toBe('0600')
        ->and($staged['content'])->toBe("secret\n");
});

it('removes the staging file when the copy fails', function () {
    $tmp = null;
    $shell = (new FakeShell)->on(INSTALL_FILE, function (array $b) use (&$tmp) {
        $tmp = $b['tmp'];
        throw new CommandFailed('sudo: a password is required');
    });

    expect(fn () => (new LinuxDriver($shell))->writeClientConfig('wg0', 'abc', 'secret'))
        ->toThrow(CommandFailed::class);

    expect($tmp)->not->toBeFile();
});

it('keeps client configs in a per-link directory', function () {
    $shell = (new FakeShell)->on(INSTALL_FILE, fn () => '');

    (new LinuxDriver($shell))->writeClientConfig('wg0', 'abc', 'secret');

    expect($shell->callsTo(INSTALL_FILE)[0]['bindings'])
        ->toMatchArray(['dir' => '/etc/wireguard/clients/wg0', 'path' => '/etc/wireguard/clients/wg0/abc.conf']);
});
