<?php

use App\Services\KeyManager;
use Symfony\Component\Process\Process;
use Tests\TestCase;

/*
 * Feature tests boot the Laravel app; unit tests run as plain test cases.
 */
pest()->extend(TestCase::class)->in('Feature');

/*
 * Each service scenario runs against a simulated host of both OSes (see Tests\Fakes\FakeHost).
 */
dataset('os', ['linux' => 'linux', 'macOS' => 'mac']);

dataset('firewall states', [
    'forward' => [true, false],
    'nat' => [false, true],
    'forward + nat' => [true, true],
]);

/** VERSION of the bundled root helper, so tests don't change with every helper release. */
function helperVersion(): string
{
    preg_match('/^VERSION=(\S+)$/m', (string) file_get_contents(__DIR__.'/../bin/wgla-helper'), $match);

    return $match[1];
}

/**
 * A wg-quick config written by hand, with what the app doesn't write: a routing table setting,
 * a hook of its own, a comment, and a keepalive other than the one the app uses for a peer the
 * server connects to.
 */
function handWrittenConf(): string
{
    $keys = new KeyManager;

    return implode("\n", [
        '[Interface]',
        'Address = 10.7.0.1/24',
        'PrivateKey = '.$keys->genkey(),
        'ListenPort = 51900',
        'Table = off',
        'PostUp = /usr/local/bin/my-routes up',
        '',
        '[Peer]',
        '# branch office',
        'PublicKey = '.$keys->pubkey($keys->genkey()),
        'AllowedIPs = 10.7.0.2/32, 192.168.9.0/24',
        'Endpoint = branch.example.com:51820',
        'PersistentKeepalive = 15',
    ]);
}

/**
 * A link as the API before this one left it: a config with hooks of its own, which open forwarding
 * in iptables and masquerade what goes to the link's destinations, and peers with a preshared key
 * and one /32 each. $extra lines go into its [Interface] section.
 *
 * @return array{conf: string, private_key: string, public_key: string, peers: list<array{public_key: string, private_key: string, preshared_key: string, ip: string}>}
 */
function legacyLink(int $peers = 3, string $extra = '', string $ifout = 'eth0'): array
{
    $keys = new KeyManager;
    $private_key = $keys->genkey();
    $rules = fn (string $action) => "iptables -{$action} FORWARD -i %i -j ACCEPT; iptables -{$action} FORWARD -o %i -j ACCEPT; iptables -t nat -{$action} POSTROUTING -d 10.20.0.0/16,192.0.2.50 -o {$ifout} -j MASQUERADE;";

    $lines = ['[Interface]', 'Address = 10.0.42.1/24', 'ListenPort = 62990', "PrivateKey = {$private_key}", 'PostUp = '.$rules('A'), 'PostDown = '.$rules('D'), ...array_filter(explode("\n", $extra))];
    $list = [];
    for ($n = 2; $n < $peers + 2; $n++) {
        $list[] = $peer = ['private_key' => $key = $keys->genkey(), 'public_key' => $keys->pubkey($key), 'preshared_key' => $keys->genpsk(), 'ip' => "10.0.42.{$n}"];
        array_push($lines, '', '[Peer]', "PublicKey = {$peer['public_key']}", "PresharedKey = {$peer['preshared_key']}", "AllowedIPs = {$peer['ip']}/32");
    }

    return ['conf' => implode("\n", $lines)."\n", 'private_key' => $private_key, 'public_key' => $keys->pubkey($private_key), 'peers' => $list];
}

/** A peer's client config as the API before this one kept it, in its link's client directory, named by the peer's address. */
function legacyClientConf(array $peer, string $link_public_key): string
{
    return "[Interface]\nPrivateKey = {$peer['private_key']}\nAddress    = {$peer['ip']}/32\nDNS        = 8.8.8.8\n\n"
        ."[Peer]\nPublicKey    = {$link_public_key}\nPresharedKey = {$peer['preshared_key']}\nAllowedIPs   = 10.20.0.0/16\nEndpoint     = 203.0.113.10:62990\nPersistentKeepalive = 25\n";
}

/*
 * A pf ruleset the real pfctl accepts (parse only: no root needed). Skipped where pfctl is missing.
 */
expect()->extend('toBeAcceptedByPf', function () {
    if (! is_executable('/sbin/pfctl')) {
        return $this;
    }

    $process = new Process(['/sbin/pfctl', '-n', '-f', '-'], input: $this->value);
    $process->run();

    expect($process->getExitCode())->toBe(0, "pfctl rejected:\n{$this->value}\n".$process->getErrorOutput());

    return $this;
});
