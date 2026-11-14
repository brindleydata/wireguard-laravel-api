<?php

use App\Services\KeyManager;
use Symfony\Component\Process\Process;
use Tests\Fakes\FakeHost;
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
 * A link config as written before format 2: no format line, and nothing of a peer's own client
 * settings in its section. They only showed in its client config, which was stored whole then:
 * store $clients (public key => client config, as getPeerConfig() builds it) the same way.
 */
function asFormat1(string $conf, ?FakeHost $host = null, string $link = '', array $clients = []): string
{
    foreach ($clients as $pubkey => $config) {
        $host->clients[$link.'/'.KeyManager::pubkeyToSafe($pubkey)] = $config;
    }

    [$header, $sections] = explode('[Interface]', $conf, 2);

    return preg_replace('/^# format = .*\n/m', '', $header).'[Interface]'.preg_replace('/^# (dns|keepalive|allowed_ips) = .*\n/m', '', $sections);
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
