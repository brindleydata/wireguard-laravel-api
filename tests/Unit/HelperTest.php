<?php

use App\Services\ConfigBuilder;
use App\Services\KeyManager;
use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use App\Validation\WireGuardValidator;
use Symfony\Component\Process\Process;
use Tests\Fakes\FakeShell;
use Tests\Support\HelperSandbox;

/*
 * The root helper (bin/wgla-helper), run unprivileged against stub system commands and temp
 * directories. The configs come from the real drivers, so these tests also pin the contract
 * between the app and the helper.
 */

const HELPER_TEST_KEY = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=';

/** The table firewall-up installs for appConf('Linux') (replies only), as `nft list` prints it */
const NFT_LISTED = "table inet wg_wg0 {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tiifname \"wg0\" accept\n\t\toifname \"wg0\" ct state established,related accept\n\t\toifname \"wg0\" drop\n\t}\n\n"
    ."\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tip saddr 10.0.0.0/24 oifname \"eth0\" masquerade\n\t}\n}";

beforeEach(function () {
    if (HelperSandbox::isRoot()) {
        $this->markTestSkipped('As root the helper ignores its test overrides and would touch the real system');
    }
});

afterEach(fn () => HelperSandbox::cleanup());

dataset('helper os', ['Linux' => 'Linux', 'macOS' => 'Darwin']);

/**
 * A link config exactly as the app writes it (hooks naming the helper under test).
 */
function appConf(string $os, bool $forward = true, bool $nat = true, ?string $address6 = null, ?int $mtu = 1380, bool $inbound = false, array $routes = [], bool $allow_default_route = false, bool $allow_own_networks = false, ?string $destinations = null, string $address = '10.0.0.1/24'): string
{
    $driver = $os === 'Darwin'
        ? new MacDriver(new FakeShell, HelperSandbox::path())
        : new LinuxDriver(new FakeShell, HelperSandbox::path());
    $keys = new KeyManager;

    return (new ConfigBuilder([], $driver))->buildConfFile(
        $address, $keys->genkey(), 51820, $os === 'Darwin' ? 'en0' : 'eth0',
        [
            ['public_key' => $keys->pubkey($keys->genkey()), 'preshared_key' => $keys->genpsk(), 'allowed_ips' => '10.0.0.2/32', 'name' => "Ана's phone (#2)",
                'dns' => '10.0.0.1, corp.example.com', 'keepalive' => '0', 'client_allowed_ips' => '10.0.0.0/24, fd00::/64'],
            // One the server connects to itself
            ['public_key' => $keys->pubkey($keys->genkey()), 'allowed_ips' => '10.0.0.3/32, fd00::3/128, 192.168.1.0/24', 'remote' => 'branch.example.com:51820'],
            // Disabled: commented out, so wg-quick doesn't load it
            ['public_key' => $keys->pubkey($keys->genkey()), 'preshared_key' => $keys->genpsk(), 'allowed_ips' => '10.0.0.4/32', 'name' => 'old laptop', 'enabled' => false, 'dns' => '9.9.9.9'],
            // $routes: what one more peer routes (a disabled one: it goes on the interface as it is when enabled)
            ...($routes === [] ? [] : [['public_key' => $keys->pubkey($keys->genkey()), 'allowed_ips' => implode(', ', ['10.0.0.5/32', ...$routes]), 'enabled' => false]]),
        ],
        '1.1.1.1, 8.8.8.8', 25, '0.0.0.0/0, ::/0', $forward, $nat, address6: $address6, mtu: $mtu,
        inbound: $inbound, allow_default_route: $allow_default_route, allow_own_networks: $allow_own_networks, destinations: $destinations,
    )."\n";
}

/**
 * What the real nft makes of a ruleset the helper writes: its listing of the table, or null where
 * that can't be asked (no nft, or no network namespace of our own to load it into without root).
 */
function listedByNft(string $ruleset, string $table): ?string
{
    if (! is_executable('/usr/bin/nft') && ! is_executable('/usr/sbin/nft')) {
        return null;
    }
    $process = new Process(['unshare', '-rn', 'sh', '-c', 'PATH=/usr/sbin:/usr/bin:/sbin:/bin; nft -f - && nft list table inet "$0"', $table], input: $ruleset);
    $process->run();
    // No namespace of our own (unshare refused): nothing was asked of nft
    if ($process->getExitCode() !== 0 && ! str_contains($process->getErrorOutput(), 'Error:')) {
        return null;
    }
    expect($process->getExitCode())->toBe(0, "nft rejected:\n{$ruleset}\n".$process->getErrorOutput());

    return rtrim($process->getOutput());
}

// ─── Arguments ──────────────────────────────────────────────────────

it('rejects malformed arguments before running anything', function (array $args, string $error) {
    $box = new HelperSandbox;

    $run = $box->run($args);

    expect($run['exit'])->not->toBe(0)
        ->and($run['stderr'])->toContain($error)
        ->and($box->calls())->toBe([]);
})->with([
    'a path as link name' => [['conf-read', '../../etc/shadow'], 'invalid link name'],
    'shell syntax in a link name' => [['up', 'wg0;id'], 'invalid link name'],
    'an option as link name' => [['down', '-rf'], 'invalid link name'],
    'a space in an interface' => [['dump', 'wg 0'], 'invalid interface name'],
    'a malformed public key' => [['peer-remove', 'wg0', 'not-a-key'], 'invalid public key'],
    'shell syntax in allowed IPs' => [['peer-ips', 'wg0', HELPER_TEST_KEY, '10.0.0.0/24;id'], 'invalid allowed IPs'],
    'a path as client key' => [['client-read', 'wg0', '../../../etc/passwd'], 'invalid client config key'],
    'shell syntax in an interface' => [['firewall-up', 'wg0', 'eth0;id'], 'invalid interface name'],
    'a missing argument' => [['up'], "'up' takes 1 argument"],
    'an extra argument' => [['up', 'wg0', 'wg1'], "'up' takes 1 argument"],
    'an unknown command' => [['bogus'], 'reinstall the helper'],
]);

it('reports its version', function () {
    expect((new HelperSandbox)->run(['version'])['stdout'])->toBe(helperVersion()."\n");
});

// ─── What peers may route ───────────────────────────────────────────

it('reports the server\'s route policy, nothing allowed without one', function () {
    $box = new HelperSandbox;
    expect($box->run(['policy'])['stdout'])->toBe("allow_default_route=false\nallow_own_networks=false\n");

    $box->policy(default_route: true);
    expect($box->run(['policy'])['stdout'])->toBe("allow_default_route=true\nallow_own_networks=false\n");
});

it('takes a peer\'s route that takes over the server\'s own traffic only where the server and the link allow it', function (string $os, string $route, string $kind, bool $server, bool $link, bool $taken) {
    $box = new HelperSandbox($os);
    $box->policy(default_route: $server && $kind === 'default', own_networks: $server && $kind === 'own');

    // On a disabled peer: it goes on the interface as it is once it's enabled
    $run = $box->run(['conf-write', 'wg0'], appConf($os, routes: [$route],
        allow_default_route: $link && $kind === 'default', allow_own_networks: $link && $kind === 'own'));

    expect($run['exit'])->toBe($taken ? 0 : 1, $run['stderr']);
    if (! $taken) {
        expect($run['stderr'])->toContain("a peer may not route {$route} here")->toContain("allow_{$kind}_")
            ->and(file_exists("{$box->confDir}/wg0.conf"))->toBeFalse();
    }
})->with('helper os')->with([
    // The host has 192.0.2.10/24 and 2001:db8:f::10/64, its gateway is 192.0.2.1
    'IPv4 default route' => ['0.0.0.0/0', 'default'],
    'IPv6 default route' => ['::/0', 'default'],
    'its LAN' => ['192.0.2.0/24', 'own'],
    'half of everything, the gateway in it' => ['0.0.0.0/1', 'own'],
    'its gateway alone' => ['192.0.2.1/32', 'own'],
    'its IPv6 prefix' => ['2001:db8:f::/48', 'own'],
])->with([
    'both allow it' => [true, true, true],
    'the server only' => [true, false, false],
    'the link only' => [false, true, false],
    'neither' => [false, false, false],
]);

it('takes networks beside the server\'s own as they are', function (string $os) {
    $box = new HelperSandbox($os);

    $run = $box->run(['conf-write', 'wg0'], appConf($os, routes: ['192.0.3.0/24', '2001:db8:e::/48', '0.0.0.0/2']));

    expect($run['exit'])->toBe(0, $run['stderr']);
})->with('helper os');

it('checks a peer added or changed on a running link against that link\'s settings', function (string $os) {
    $box = new HelperSandbox($os);
    $iface = $os === 'Darwin' ? 'utun5' : 'wg0';
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $peer = fn (string $ips) => "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\nAllowedIPs = {$ips}\n";
    $box->policy(default_route: true);
    $box->writeConf('wg0', appConf($os));

    expect($box->run(['peer-add', $iface], $peer('10.0.0.9/32, 0.0.0.0/0'))['exit'])->toBe(1, 'The link does not allow it')
        ->and($box->run(['peer-ips', $iface, HELPER_TEST_KEY, '10.0.0.9/32, 0.0.0.0/0'])['exit'])->toBe(1)
        ->and($box->run(['peer-add', $iface], $peer('10.0.0.9/32, 192.0.2.0/25'))['exit'])->toBe(1, 'Nor its own networks')
        ->and($box->calls())->toBe([]);

    $box->writeConf('wg0', appConf($os, allow_default_route: true));
    expect($box->run(['peer-add', $iface], $peer('10.0.0.9/32, 0.0.0.0/0'))['exit'])->toBe(0)
        ->and($box->run(['peer-ips', $iface, HELPER_TEST_KEY, '10.0.0.9/32, 0.0.0.0/0'])['exit'])->toBe(0)
        ->and($box->calls())->toHaveCount(2);
})->with('helper os');

// ─── Link configs ───────────────────────────────────────────────────

it('stores exactly the link configs the app writes', function (string $os) {
    $box = new HelperSandbox($os);
    $hooked = appConf($os);
    $plain = appConf($os, forward: false, nat: false);
    $dual = appConf($os, address6: 'fd12:3456:789a::1/64');

    $run = $box->run(['conf-write', 'wg0'], $hooked);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->run(['conf-write', 'wg1'], $plain)['exit'])->toBe(0)
        ->and($box->run(['conf-write', 'wg2'], $dual)['exit'])->toBe(0)
        ->and($dual)->toContain("# address6 = fd12:3456:789a::1/64\n")->toContain("Address = 10.0.0.1/24, fd12:3456:789a::1/64\n")
        ->and($hooked)->toContain("# nat = true\n# inbound = false\n# format = 2\n", "ListenPort = 51820\nMTU = 1380\n")->not->toContain('# up')
        ->toContain("AllowedIPs = 10.0.0.3/32, fd00::3/128, 192.168.1.0/24\nEndpoint = branch.example.com:51820\nPersistentKeepalive = 25\n")
        ->toContain("[Peer]\n# name = Ана's phone (#2)\n# dns = 10.0.0.1, corp.example.com\n# keepalive = 0\n# allowed_ips = 10.0.0.0/24, fd00::/64\nPublicKey = ")
        ->toContain("# [Peer] disabled\n# name = old laptop\n# dns = 9.9.9.9\n# PublicKey = ")
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($hooked)
        ->and(sprintf('%o', fileperms("{$box->confDir}/wg0.conf") & 0777))->toBe('600')
        ->and($box->run(['conf-read', 'wg0'])['stdout'])->toBe($hooked)
        ->and($box->run(['conf-list'])['stdout'])->toBe("wg0\nwg1\nwg2\n")
        ->and($box->calls())->toBe([]);
})->with('helper os');

it('rejects anything else in a link config and keeps the saved one', function (string $pattern, string $replacement, string $error) {
    $box = new HelperSandbox('Linux');
    $saved = appConf('Linux');
    $box->writeConf('wg0', $saved);

    $run = $box->run(['conf-write', 'wg0'], preg_replace($pattern, $replacement, $saved));

    expect($run['exit'])->not->toBe(0)
        ->and($run['stderr'])->toContain($error)
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($saved)
        ->and(glob("{$box->confDir}/.wgla.*"))->toBe([], 'No temp file is left behind');
})->with([
    'a root command as PostUp' => ['/^PostUp = .*$/m', 'PostUp = touch /tmp/pwned', 'PostUp must be exactly'],
    'another helper as hook' => ['/^(PostUp = )\S+/m', '$1/tmp/evil', 'PostUp must be exactly'],
    'a root command as PostDown' => ['/^PostDown = .*$/m', 'PostDown = id', 'PostDown must be exactly'],
    'an extra PreUp hook' => ['/^ListenPort/m', "PreUp = id\nListenPort", 'not allowed in a link config: PreUp = id'],
    'DNS (runs resolvconf)' => ['/^ListenPort/m', "DNS = 1.1.1.1\nListenPort", 'not allowed in a link config: DNS'],
    'Table' => ['/^ListenPort/m', "Table = off\nListenPort", 'not allowed in a link config: Table'],
    'SaveConfig' => ['/^ListenPort/m', "SaveConfig = true\nListenPort", 'not allowed in a link config: SaveConfig'],
    'shell syntax in where to connect to a peer' => ['/^\[Peer\]$/m', "[Peer]\nEndpoint = 203.0.113.1:51820;id", 'not allowed in a link config: Endpoint'],
    'an endpoint without a port' => ['/^\[Peer\]$/m', "[Peer]\nEndpoint = branch.example.com", 'not allowed in a link config: Endpoint'],
    'a keepalive out of range' => ['/^\[Peer\]$/m', "[Peer]\nPersistentKeepalive = 70000", 'not allowed in a link config: PersistentKeepalive'],
    'an MTU too small to be one' => ['/^ListenPort/m', "MTU = 100\nListenPort", 'not allowed in a link config: MTU'],
    'shell syntax in metadata' => ['/^# ifout = .*$/m', '# ifout = eth0;id', 'metadata not allowed'],
    'shell syntax in an IPv6 address' => ['/^# address = .*$/m', "# address = 10.0.0.1/24\n# address6 = fd12::1/64;id", 'metadata not allowed'],
    'a second IPv6 address' => ['/^Address = .*$/m', 'Address = 10.0.0.1/24, fd12::1/64, fd13::1/64', 'not allowed in a link config: Address'],
    'an IPv6-only address' => ['/^Address = .*$/m', 'Address = fd12::1/64', 'not allowed in a link config: Address'],
    'a malformed IPv6 address' => ['/^Address = .*$/m', 'Address = 10.0.0.1/24, fd12:::1/64', 'not allowed in a link config: Address'],
    // "08" is no number to the shell arithmetic the firewall rules are built with
    'a mask with a leading zero' => ['/^# address = .*$/m', '# address = 10.0.0.1/08', 'metadata not allowed'],
    'an octet with a leading zero' => ['/^Address = .*$/m', 'Address = 10.0.0.01/24', 'not allowed in a link config: Address'],
    'spaces around a comma in a list' => ['/^# dns = .*$/m', '# dns = 1.1.1.1 , 8.8.8.8', 'metadata not allowed'],
    'unknown metadata' => ['/^/', "# owner = me\n", 'metadata not allowed'],
    'a comment after [Interface]' => ['/^\[Peer\]$/m', "# note\n[Peer]", 'comments are only allowed before [Interface]'],
    'a peer name in [Interface]' => ['/^ListenPort/m', "# name = me\nListenPort", 'comments are only allowed before [Interface]'],
    'a peer name before [Interface]' => ['/^/', "# name = me\n", 'metadata not allowed'],
    'a control character in a peer name' => ['/^# name = old laptop$/m', "# name = old\x1b[2Jlaptop", 'invalid peer name'],
    'an empty peer name' => ['/^# name = old laptop$/m', '# name = ', 'invalid peer name'],
    'shell syntax in a peer\'s DNS' => ['/^# dns = 9\.9\.9\.9$/m', '# dns = 9.9.9.9;id', 'metadata not allowed'],
    'a peer keepalive out of range' => ['/^# keepalive = 0$/m', '# keepalive = 70000', 'metadata not allowed'],
    'a hostname in a peer\'s allowed IPs' => ['/^# allowed_ips = 10\.0\.0\.0\/24, fd00::\/64$/m', '# allowed_ips = example.com', 'metadata not allowed'],
    'a link setting in a peer' => ['/^# name = old laptop$/m', "# name = old laptop\n# nat = true", 'not allowed in a link config: nat = true'],
    'a peer setting in [Interface]' => ['/^ListenPort/m', "# keepalive = 5\nListenPort", 'comments are only allowed before [Interface]'],
    'a format that is no number' => ['/^# format = .*$/m', '# format = two', 'metadata not allowed'],
    'a hook in a disabled peer' => ['/^# \[Peer\] disabled$/m', "# [Peer] disabled\n# PostUp = id", 'not allowed in a link config: PostUp = id'],
    'a bad key in a disabled peer' => ['/^(# PublicKey = ).*$/m', '$1not-a-key', 'not allowed in a link config: PublicKey = not-a-key'],
    'free text in a disabled peer' => ['/^# \[Peer\] disabled$/m', "# [Peer] disabled\n# remember to delete", 'malformed line in a disabled peer'],
    'a second [Interface]' => ['/\z/', "[Interface]\n", '[Interface] must come first, once'],
    'no [Interface]' => ['/\A[\s\S]*\z/', "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\n", '[Peer] before [Interface]'],
    'more than 1 MB' => ['/\z/', str_repeat("#\n", 600000), 'larger than'],
]);

it('takes the lists the validator hands on, however they were typed', function () {
    $box = new HelperSandbox('Linux');
    $validator = new WireGuardValidator;
    $driver = new LinuxDriver(new FakeShell, HelperSandbox::path());

    $conf = (new ConfigBuilder([], $driver))->buildConfFile(
        '10.0.0.1/24', (new KeyManager)->genkey(), 51820, 'eth0',
        dns: $validator->validateDns(' 1.1.1.1 ,  8.8.8.8,corp.example.com'),
        allowed_ips: $validator->validateAllowedIps('10.0.0.0/8 ,192.168.0.0/16,  ::/0'),
    )."\n";

    $run = $box->run(['conf-write', 'wg0'], $conf);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($conf)->toContain("# dns = 1.1.1.1, 8.8.8.8, corp.example.com\n", "# allowed_ips = 10.0.0.0/8, 192.168.0.0/16, ::/0\n");
});

it('answers a config that is not there with exit status 3, and an error with another', function () {
    $box = new HelperSandbox;
    $key = rtrim(strtr(HELPER_TEST_KEY, '+/', '-_'), '=');

    // The app reads 3 as "no such link" and anything else as a failure
    expect($box->run(['conf-read', 'wg0'])['exit'])->toBe(3)
        ->and($box->run(['client-read', 'wg0', $key])['exit'])->toBe(3)
        ->and($box->run(['conf-read', '../etc/shadow'])['exit'])->toBe(1)
        ->and($box->run(['client-read', 'wg0', 'not-a-key'])['exit'])->toBe(1)
        ->and($box->run(['up', 'wg0'])['exit'])->toBe(1, 'Starting a link without a config is an error');
});

it('lists only configs with valid link names', function () {
    $box = new HelperSandbox;
    foreach (['wg0.conf', 'bad name.conf', '.hidden.conf', 'notes.txt'] as $file) {
        touch("{$box->confDir}/{$file}");
    }

    expect($box->run(['conf-list'])['stdout'])->toBe("wg0\n");
});

// ─── Peers and client configs ───────────────────────────────────────

it('adds a validated peer to a running interface', function (string $where) {
    $box = new HelperSandbox;
    $peer = "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\nPresharedKey = ".HELPER_TEST_KEY."\nAllowedIPs = 10.0.0.2/32\n{$where}";

    expect($box->run(['peer-add', 'wg0'], $peer)['exit'])->toBe(0)
        ->and($box->calls())->toBe([['wg', 'addconf', 'wg0', '/dev/stdin']])
        ->and($box->stdin())->toBe([$peer]);
})->with([
    'one that connects to the server' => '',
    'one the server connects to' => "Endpoint = branch.example.com:51820\nPersistentKeepalive = 25\n",
    'one at an IPv6 address' => "Endpoint = [2001:db8::7]:51820\nPersistentKeepalive = 25\n",
]);

it('runs wg in the C locale, trying a name that does not resolve only a few times', function () {
    // By default wg retries for minutes: the app's call would time out and leave wg running.
    // The locale is the helper's own too: what its checks match can't depend on the caller's.
    $box = new HelperSandbox;
    // It reads its stdin as `wg addconf … /dev/stdin` does: one that exits first breaks the
    // helper's pipe into it (cat: Broken pipe), whenever it wins that race
    file_put_contents("{$box->dir}/stubs/wg", "#!/bin/sh\ncat > /dev/null\necho \"retries=\$WG_ENDPOINT_RESOLUTION_RETRIES locale=\$LC_ALL\"\n");
    chmod("{$box->dir}/stubs/wg", 0755);

    $run = $box->run(['peer-add', 'wg0'], "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\nAllowedIPs = 10.0.0.2/32\nEndpoint = branch.example.com:51820\n");

    expect($run['exit'])->toBe(0, $run['stderr'])->and($run['stdout'])->toBe("retries=2 locale=C\n");
});

it('gives a running link a new private key, on stdin only', function () {
    $box = new HelperSandbox;

    expect($box->run(['link-key', 'wg0'], HELPER_TEST_KEY."\n")['exit'])->toBe(0)
        ->and($box->calls())->toBe([['wg', 'set', 'wg0', 'private-key', '/dev/stdin']])
        ->and($box->stdin())->toBe([HELPER_TEST_KEY."\n"])
        ->and($box->run(['link-key', 'wg0'], "not a key\n")['exit'])->toBe(1)
        ->and($box->calls())->toHaveCount(1);
});

it('takes where a link\'s clients connect, and nothing else in that line', function (string $endpoint, bool $taken) {
    $box = new HelperSandbox;

    $run = $box->run(['conf-write', 'wg0'], str_replace('# forward = ', "# endpoint = {$endpoint}\n# forward = ", appConf('Linux')));

    expect($run['exit'])->toBe($taken ? 0 : 1, $run['stderr']);
})->with([
    'a name' => ['vpn.example.com', true],
    'a name and port' => ['vpn.example.com:443', true],
    'an IPv6 address' => ['[2001:db8::7]', true],
    'with a port' => ['[2001:db8::7]:443', true],
    'shell syntax' => ['vpn.example.com;id', false],
    'a bare IPv6 address' => ['2001:db8::7', false],
]);

it('sets allowed IPs of both families in the form wg takes', function () {
    $box = new HelperSandbox;

    expect($box->run(['peer-ips', 'wg0', HELPER_TEST_KEY, '10.0.0.2/32, fd12::2/128'])['exit'])->toBe(0)
        ->and($box->calls())->toBe([['wg', 'set', 'wg0', 'peer', HELPER_TEST_KEY, 'allowed-ips', '10.0.0.2/32,fd12::2/128']]);
});

it('rejects a peer with anything but keys, allowed IPs and where to connect to it', function (string $extra) {
    $box = new HelperSandbox;

    $run = $box->run(['peer-add', 'wg0'], "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\n{$extra}\n");

    expect($run['exit'])->not->toBe(0)->and($box->calls())->toBe([]);
})->with([
    'shell syntax in an endpoint' => 'Endpoint = 203.0.113.1:51820;id',
    'a keepalive out of range' => 'PersistentKeepalive = 70000',
    'a hook' => 'PostUp = id',
    'an [Interface] section' => "[Interface]\nPrivateKey = ".HELPER_TEST_KEY,
    'shell syntax in allowed IPs' => 'AllowedIPs = 10.0.0.2/32;id',
]);

it('stores client configs privately under their link', function () {
    $box = new HelperSandbox;
    $key = rtrim(strtr(HELPER_TEST_KEY, '+/', '-_'), '=');
    $file = "{$box->confDir}/clients/wg0/{$key}.conf";

    expect($box->run(['client-write', 'wg0', $key], "[Interface]\n")['exit'])->toBe(0)
        ->and(sprintf('%o', fileperms($file) & 0777))->toBe('600')
        ->and(sprintf('%o', fileperms(dirname($file)) & 0777))->toBe('700')
        ->and($box->run(['client-read', 'wg0', $key])['stdout'])->toBe("[Interface]\n");

    $box->run(['client-delete-all', 'wg0']);

    expect(dirname($file))->not->toBeDirectory();
});

// ─── Lifecycle ──────────────────────────────────────────────────────

it('runs links as systemd units on Linux', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux'));

    $box->run(['up', 'wg0']);
    $box->run(['down', 'wg0']);
    $box->run(['down', 'wg1']); // idempotent, also for a link that isn't there

    expect($box->calls())->toBe([
        ['systemctl', 'enable', '--now', 'wg-quick@wg0'],
        ['systemctl', 'disable', '--now', 'wg-quick@wg0'],
        ['systemctl', 'disable', '--now', 'wg-quick@wg1'],
    ]);
});

it('runs links with wg-quick and their full config path on macOS', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin'));

    $box->run(['up', 'wg0']);
    $box->run(['down', 'wg0']); // no name file: not running, nothing to do
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->run(['down', 'wg0']);

    expect($box->calls())->toBe([
        ['wg-quick', 'up', "{$box->confDir}/wg0.conf"],
        ['wg-quick', 'down', "{$box->confDir}/wg0.conf"],
    ]);
});

it('refuses to start a link without a config', function (string $os) {
    $box = new HelperSandbox($os);

    $run = $box->run(['up', 'wg9']);

    expect($run['exit'])->not->toBe(0)
        ->and($run['stderr'])->toContain('no config for link wg9')
        ->and($box->calls())->toBe([]);
})->with('helper os');

it('resolves the utun interface wg-quick created on macOS', function () {
    $box = new HelperSandbox('Darwin');
    file_put_contents("{$box->runDir}/wg0.name", "utun7\n");
    file_put_contents("{$box->runDir}/bad.name", "utun7; rm -rf /\n");

    expect($box->run(['resolve', 'wg0'])['stdout'])->toBe("utun7\n")
        ->and($box->run(['resolve', 'wg1'])['stdout'])->toBe("wg1\n", 'No name file: link is down')
        ->and($box->run(['resolve', 'bad'])['stdout'])->toBe("bad\n", 'Unexpected content is ignored')
        ->and((new HelperSandbox('Linux'))->run(['resolve', 'wg0'])['stdout'])->toBe("wg0\n");
});

// ─── Firewall ───────────────────────────────────────────────────────

it('installs the link nftables table from its saved config', function (bool $inbound, string $into) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', inbound: $inbound));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin())->toBe([<<<NFT
            table inet wg_wg0
            delete table inet wg_wg0
            table inet wg_wg0 {
                chain forward { type filter hook forward priority 0; iifname "wg0" accept; {$into} }
                chain postrouting { type nat hook postrouting priority 100; ip saddr 10.0.0.0/24 oifname "eth0" masquerade; }
            }

            NFT])
        ->and(array_filter($box->calls(), fn ($call) => in_array('-I', $call, true)))->toBe([], 'Nothing in iptables drops forwarded traffic');
})->with([
    // Into the tunnel: what answers its peers, and only with `inbound` what starts outside
    // (the rest dropped: the chain's policy would accept it)
    'replies only' => [false, 'oifname "wg0" ct state established,related accept; oifname "wg0" drop;'],
    'inbound' => [true, 'oifname "wg0" accept;'],
]);

it('opens the iptables FORWARD chain when Docker or ufw drop forwarded traffic', function (bool $inbound, array $into) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', inbound: $inbound));
    $box->respond('iptables -S FORWARD', implode("\n", [
        // As real iptables prints them: the comment is quoted
        '-P FORWARD DROP',
        '-A FORWARD -i wg0 -m comment --comment "wgla:wg0" -j ACCEPT',
        '-A FORWARD -o wg0 -m comment --comment wgla:wg0 -j ACCEPT',
        '-A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "wgla:wg0" -j ACCEPT',
        '-A FORWARD -i wg01 -m comment --comment "wgla:wg01" -j ACCEPT',
        '-A FORWARD -j DOCKER-USER',
    ]));

    $box->run(['firewall-up', 'wg0', 'wg0']);

    expect(array_values(array_filter($box->calls(), fn ($call) => $call[0] === 'iptables' && $call[1] !== '-S')))->toBe([
        ['iptables', '-D', 'FORWARD', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-D', 'FORWARD', '-o', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-D', 'FORWARD', '-o', 'wg0', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-I', 'FORWARD', '1', '-o', 'wg0', ...$into, '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-I', 'FORWARD', '1', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
    ]);
})->with([
    'replies only' => [false, ['-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED']],
    'inbound' => [true, []],
]);

it('masquerades the IPv6 prefix too on a dual-stack link', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', address6: 'fd12:3456:789a::1/64'));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin()[0])->toContain('chain postrouting { type nat hook postrouting priority 100; '
            .'ip saddr 10.0.0.0/24 oifname "eth0" masquerade; ip6 saddr fd12:3456:789a::1/64 oifname "eth0" masquerade; }');
});

it('opens the ip6tables FORWARD chain too when it drops forwarded traffic', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', address6: 'fd12:3456:789a::1/64'));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    $box->respond('ip6tables -S FORWARD', "-P FORWARD DROP\n-A FORWARD -i wg0 -m comment --comment \"wgla:wg0\" -j ACCEPT");

    $box->run(['firewall-up', 'wg0', 'wg0']);

    expect(array_values(array_filter($box->calls(), fn ($call) => $call[1] !== '-S' && str_contains($call[0], 'tables'))))->toBe([
        ['ip6tables', '-D', 'FORWARD', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['ip6tables', '-I', 'FORWARD', '1', '-o', 'wg0', '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['ip6tables', '-I', 'FORWARD', '1', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
    ]);
});

it('leaves iptables and ip6tables alone when they are not installed', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux'));
    $box->uninstall('iptables');
    $box->uninstall('ip6tables');

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and(array_column($box->calls(), 0))->toBe(['nft']);
});

it('loads nat before pass rules into the link pf anchor', function (bool $inbound, string $pass) {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', inbound: $inbound));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n"); // wg-quick records it before PostUp

    $run = $box->run(['firewall-up', 'wg0', 'utun5']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->calls())->toBe([['pfctl', '-a', 'wg/wg0', '-f', '-'], ['pfctl', '-e']])
        ->and($box->stdin()[0])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\n{$pass}")
        ->toBeAcceptedByPf();
})->with([
    // pf keeps state: what peers start (in on the utun) is answered. What comes in elsewhere for the
    // link's addresses is tagged without state, and dropped on its way out to the utun
    'replies only' => [false, "pass in on utun5 all\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0\n"],
    'inbound' => [true, "pass in on utun5 all\npass out on utun5 all\n"],
]);

it('adds an IPv6 nat rule to the pf anchor of a dual-stack link', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', address6: 'fd12:3456:789a::1/64'));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    $run = $box->run(['firewall-up', 'wg0', 'utun5']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin()[0])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\nnat on en0 inet6 from fd12:3456:789a::1/64 to any -> (en0)\n"
            ."pass in on utun5 all\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\n"
            ."pass in on ! utun5 inet6 from any to fd12:3456:789a::1/64 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0\n")
        ->toBeAcceptedByPf();
});

it('installs rules for the link\'s own interface only', function (string $os, string $iface) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->respond('iptables -S FORWARD', "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER");

    // Forward accepts for another interface would open what the host's firewall closed
    $run = $box->run(['firewall-up', 'wg0', $iface]);

    expect($run['exit'])->toBe(1)
        ->and($run['stderr'])->toContain("{$iface} is not the interface of link wg0")
        ->and($box->calls())->toBe([]);
})->with([
    'Linux: another interface' => ['Linux', 'docker0'],
    'macOS: another utun' => ['Darwin', 'utun9'],
    'macOS: the link name' => ['Darwin', 'wg0'],
]);

it('installs only the rules that are enabled', function (string $os, bool $forward, bool $nat) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os, $forward, $nat));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    $run = $box->run(['firewall-up', 'wg0', $os === 'Darwin' ? 'utun5' : 'wg0']);
    $rules = $box->stdin()[0];

    expect($run['exit'])->toBe(0, $run['stderr']);
    if ($os === 'Darwin') {
        expect(str_contains($rules, 'pass in on utun5'))->toBe($forward)
            ->and(str_contains($rules, 'nat on en0'))->toBe($nat)
            ->and($rules)->toBeAcceptedByPf();
    } else {
        expect(str_contains($rules, 'chain forward'))->toBe($forward)
            ->and(str_contains($rules, 'masquerade'))->toBe($nat);
    }
})->with('helper os')->with('firewall states');

it('clears the rules when forward and NAT are both off', function (string $os) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os, forward: false, nat: false));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    $box->run(['firewall-up', 'wg0', $os === 'Darwin' ? 'utun5' : 'wg0']);

    expect($os === 'Darwin'
        ? $box->calls() === [['pfctl', '-a', 'wg/wg0', '-F', 'all']]
        : $box->stdin() === ["table inet wg_wg0\ndelete table inet wg_wg0\n"]
    )->toBeTrue();
})->with('helper os');

it('clears the link firewall and tolerates there being nothing to clear', function (string $os) {
    $box = new HelperSandbox($os);
    $box->failing($os === 'Darwin' ? 'pfctl' : 'nft');
    $box->respond('iptables -S FORWARD', "-P FORWARD DROP\n-A FORWARD -i wg0 -m comment --comment \"wgla:wg0\" -j ACCEPT");

    $run = $box->run(['firewall-down', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->calls())->toContain($os === 'Darwin'
            ? ['pfctl', '-a', 'wg/wg0', '-F', 'all']
            : ['nft', 'delete', 'table', 'inet', 'wg_wg0']);
    if ($os === 'Linux') {
        expect($box->calls())->toContain(['iptables', '-D', 'FORWARD', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT']);
    }
})->with('helper os');

// ─── Rules that went missing ────────────────────────────────────────

it('says whether a link still has the rules its config asks for', function (string $os, bool $present) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os));
    $iface = $os === 'Darwin' ? 'utun5' : 'wg0';
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    if ($os === 'Darwin') {
        $box->respond('pfctl -a wg/wg0 -s nat', $present ? 'nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin' : '');
        // As pfctl prints them
        $box->respond('pfctl -a wg/wg0 -s rules', $present ? "pass in on utun5 all flags S/SA keep state\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0" : '');
    } elseif ($present) {
        $box->respond('nft list table inet wg_wg0', NFT_LISTED);
    } else {
        // As after `nft -f` of a ruleset that starts with "flush ruleset"
        $box->respond('nft list table inet wg_wg0', '', 1);
    }

    $run = $box->run(['firewall-check', 'wg0', $iface]);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toBe($present ? "ok\n" : "missing\n");
})->with('helper os')->with(['in place' => true, 'gone' => false]);

it('misses its accepts in an iptables chain that drops forwarded traffic', function (string $listing, string $answer) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', nat: false));
    $box->respond('nft list table inet wg_wg0', "table inet wg_wg0 {\n\tchain forward {\n\t\tiifname \"wg0\" accept\n\t\toifname \"wg0\" ct state established,related accept\n\t\toifname \"wg0\" drop\n\t}\n}");
    $box->respond('iptables -S FORWARD', $listing);

    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("{$answer}\n");
})->with([
    'both there' => ["-P FORWARD DROP\n-A FORWARD -i wg0 -m comment --comment \"wgla:wg0\" -j ACCEPT\n-A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"wgla:wg0\" -j ACCEPT\n-A FORWARD -j DOCKER-USER", 'ok'],
    'gone after a Docker or ufw restart' => ["-P FORWARD DROP\n-A FORWARD -j DOCKER-USER", 'missing'],
    'nothing drops' => ['-P FORWARD ACCEPT', 'ok'],
    // From before the link was replies-only: it takes connections in that it shouldn't
    'one that takes connections in' => ["-P FORWARD DROP\n-A FORWARD -i wg0 -m comment --comment \"wgla:wg0\" -j ACCEPT\n-A FORWARD -o wg0 -m comment --comment \"wgla:wg0\" -j ACCEPT", 'missing'],
    // wgla:wg0 is a prefix of these: they are another link's
    'only those of wg01' => ["-P FORWARD DROP\n-A FORWARD -i wg01 -m comment --comment \"wgla:wg01\" -j ACCEPT\n-A FORWARD -o wg01 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment \"wgla:wg01\" -j ACCEPT", 'missing'],
    'only those of wg0-site' => ["-P FORWARD DROP\n-A FORWARD -i wg0-site -m comment --comment wgla:wg0-site -j ACCEPT\n-A FORWARD -o wg0-site -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment wgla:wg0-site -j ACCEPT", 'missing'],
]);

it('misses rules that are there, but not the ones the config asks for now', function (string $config, string $listed) {
    // The old check only looked for the word "masquerade" and one accept
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', $config);
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    $box->respond('nft list table inet wg_wg0', $listed);

    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("missing\n");
})->with([
    'NAT out of the interface it went out of before' => [appConf('Linux'), str_replace('oifname "eth0"', 'oifname "eth1"', NFT_LISTED)],
    'NAT of another subnet' => [appConf('Linux'), str_replace('10.0.0.0/24', '10.9.0.0/24', NFT_LISTED)],
    'no NAT for the IPv6 prefix' => [appConf('Linux', address6: 'fd12:3456:789a::1/64'), NFT_LISTED],
    'connections in, where only replies are asked for' => [appConf('Linux'), str_replace([' ct state established,related', "\t\toifname \"wg0\" drop\n"], '', NFT_LISTED)],
    'only replies, where connections in are asked for' => [appConf('Linux', inbound: true), NFT_LISTED],
]);

it('finds macOS\'s replies-only rules as pfctl prints them, and misses them when they are not', function (string $rules, string $answer) {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', address6: 'fd12:3456:789a::1/64'));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->respond('pfctl -a wg/wg0 -s nat', "nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin\nnat on en0 inet6 from fd12:3456:789a::/64 to any -> (en0) round-robin");
    $box->respond('pfctl -a wg/wg0 -s rules', $rules);

    expect($box->run(['firewall-check', 'wg0', 'utun5'])['stdout'])->toBe("{$answer}\n");
})->with([
    // The prefix with its host bits masked, as pfctl prints it
    'all there' => ["pass in on utun5 all flags S/SA keep state\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\npass in on ! utun5 inet6 from any to fd12:3456:789a::/64 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0", 'ok'],
    'nothing dropped' => ["pass in on utun5 all flags S/SA keep state\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\npass in on ! utun5 inet6 from any to fd12:3456:789a::/64 no state tag wgla_in_wg0", 'missing'],
    'connections in' => ["pass in on utun5 all flags S/SA keep state\npass out on utun5 all flags S/SA keep state", 'missing'],
]);

it('finds NAT for the IPv6 prefix as nft prints it', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', address6: 'fd12:3456:789a::1/64'));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    // The host bits masked
    $box->respond('nft list table inet wg_wg0', str_replace("masquerade\n", "masquerade\n\t\tip6 saddr fd12:3456:789a::/64 oifname \"eth0\" masquerade\n", NFT_LISTED));

    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("ok\n");
});

it('has nothing to miss for a link without forward or NAT', function (string $os) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os, forward: false, nat: false));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    expect($box->run(['firewall-check', 'wg0', $os === 'Darwin' ? 'utun5' : 'wg0'])['stdout'])->toBe("ok\n")
        ->and($box->calls())->toBe([]);
})->with('helper os');

it('puts the rules back for every running link that lost them, and only for those', function () {
    $box = new HelperSandbox('Linux');
    foreach (['wg0', 'wg1', 'wg2'] as $link) {
        $box->writeConf($link, appConf('Linux'));
    }
    $box->writeConf('wg3', "this is no config\n"); // must not stop the others
    $box->respond('wg show interfaces', 'wg0 wg1 wg3 unmanaged9');
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    $box->respond('nft list table inet wg_wg0', '', 1);
    $box->respond('nft list table inet wg_wg1', str_replace('"wg0"', '"wg1"', NFT_LISTED));

    $run = $box->run(['firewall-repair']);

    // wg0 lost them; wg1 has them; wg2 isn't running; wg3 and the interface without a config are skipped
    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toBe("<4>wgla-helper: link wg0 had lost its firewall rules; they are back\n")
        ->and(array_values(array_filter($box->calls(), fn (array $call) => $call === ['nft', '-f', '-'])))->toHaveCount(1)
        ->and($box->stdin()[0])->toContain('table inet wg_wg0 {', 'iifname "wg0" accept');
});

it('says so when putting the rules back fails, instead of that they are back', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux'));
    $box->respond('wg show interfaces', 'wg0');
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    $box->failing('nft'); // listing (gone) and loading (refused) alike

    $run = $box->run(['firewall-repair']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toBe("<3>wgla-helper: link wg0 is missing its firewall rules, and they could not be put back\n")
        ->and($box->calls())->not->toContain(['iptables', '-S', 'FORWARD'], 'Nothing after the failed nft');
});

it('repairs the link behind each utun on macOS', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin'));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->respond('wg show interfaces', 'utun5 utun9');

    $run = $box->run(['firewall-repair']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toContain('link wg0 had lost its firewall rules')
        ->and($box->calls())->toContain(['pfctl', '-a', 'wg/wg0', '-f', '-'])
        ->and($box->stdin()[0])->toContain('pass in on utun5 all')->toBeAcceptedByPf();
});

// ─── A link's destinations ──────────────────────────────────────────

/** Destinations of both families, as the app writes them */
const HELPER_DESTINATIONS = '10.20.0.0/16, 192.0.2.50/32, 2001:db8:a::/48';

/** The table firewall-up installs for appConf('Linux', destinations: HELPER_DESTINATIONS) on a dual-stack link, as `nft list` prints it: each network its own way */
const NFT_LISTED_SCOPED = "table inet wg_wg0 {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tiifname \"wg0\" ct state established,related accept\n"
    ."\t\tiifname \"wg0\" ip daddr 10.20.0.0/16 accept\n\t\tiifname \"wg0\" ip daddr 192.0.2.50 accept\n\t\tiifname \"wg0\" ip6 daddr 2001:db8:a::/48 accept\n\t\tiifname \"wg0\" drop\n"
    ."\t\toifname \"wg0\" ct state established,related accept\n\t\toifname \"wg0\" drop\n\t}\n\n"
    ."\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tip saddr 10.0.0.0/24 ip daddr 10.20.0.0/16 oifname \"eth0\" masquerade\n"
    ."\t\tip saddr 10.0.0.0/24 ip daddr 192.0.2.50 oifname \"eth0\" masquerade\n\t\tip6 saddr fd12:3456:789a::/64 ip6 daddr 2001:db8:a::/48 oifname \"eth0\" masquerade\n\t}\n}";

it('takes a link\'s destinations, and nothing else in that line', function (string $destinations, bool $taken) {
    $box = new HelperSandbox;

    $run = $box->run(['conf-write', 'wg0'], str_replace('# format = ', "# destinations = {$destinations}\n# format = ", appConf('Linux')));

    expect($run['exit'])->toBe($taken ? 0 : 1, $run['stderr']);
    if (! $taken) {
        expect($run['stderr'])->toContain('metadata not allowed: # destinations');
    }
})->with([
    'networks of both families' => [HELPER_DESTINATIONS.', fd00::7/128', true],
    'one' => ['10.20.0.0/16', true],
    'half of everything' => ['0.0.0.0/1, 128.0.0.0/1', true],
    // What a link without destinations has: the app never writes it
    'everything' => ['0.0.0.0/0', false],
    'everything, in IPv6' => ['10.20.0.0/16, ::/0', false],
    'everything, written long' => ['::/00', false],
    'a mask with a leading zero' => ['10.20.0.0/016', false],
    'an address without its mask' => ['10.20.0.1', false],
    'a name' => ['pbx.example.com', false],
    'shell syntax' => ['10.20.0.0/16;id', false],
    'more of a rule' => ['10.20.0.0/16 accept', false],
    'an IPv6 address that is none' => ['12345::/64', false],
    'an IPv6 address with too many groups' => ['1:2:3:4:5:6:7:8:9/64', false],
    'spaces around a comma' => ['10.20.0.0/16 , 10.30.0.0/16', false],
]);

it('forwards out of the tunnel and masquerades only to the link\'s destinations', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', address6: 'fd12:3456:789a::1/64', destinations: HELPER_DESTINATIONS));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    // A rule per destination, and the rest out of the tunnel dropped (but replies to what came in
    // for its peers): a drop in this table is final, whatever another one accepts
    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin())->toBe([<<<'NFT'
            table inet wg_wg0
            delete table inet wg_wg0
            table inet wg_wg0 {
                chain forward { type filter hook forward priority 0; iifname "wg0" ct state established,related accept; iifname "wg0" ip daddr 10.20.0.0/16 accept; iifname "wg0" ip daddr 192.0.2.50/32 accept; iifname "wg0" ip6 daddr 2001:db8:a::/48 accept; iifname "wg0" drop; oifname "wg0" ct state established,related accept; oifname "wg0" drop; }
                chain postrouting { type nat hook postrouting priority 100; ip saddr 10.0.0.0/24 ip daddr 10.20.0.0/16 oifname "eth0" masquerade; ip saddr 10.0.0.0/24 ip daddr 192.0.2.50/32 oifname "eth0" masquerade; ip6 saddr fd12:3456:789a::1/64 ip6 daddr 2001:db8:a::/48 oifname "eth0" masquerade; }
            }

            NFT]);
});

it('holds a link to its destinations with or without forward and NAT', function (bool $forward, bool $nat, bool $inbound, string $chains) {
    $box = new HelperSandbox('Linux');
    // Only IPv4 destinations: nothing of IPv6 gets out of the tunnel then
    $box->writeConf('wg0', appConf('Linux', $forward, $nat, address6: 'fd12:3456:789a::1/64', inbound: $inbound, destinations: '10.20.0.0/16'));
    $box->respond('iptables -S FORWARD', "-P FORWARD DROP\n-A FORWARD -j DOCKER-USER");

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin()[0])->toBe("table inet wg_wg0\ndelete table inet wg_wg0\ntable inet wg_wg0 {\n{$chains}}\n")
        // Opening iptables' own FORWARD chain is still only forward's to ask for
        ->and(array_filter($box->calls(), fn (array $call) => in_array('-I', $call, true)) !== [])->toBe($forward);
})->with([
    'neither: only what leaves the tunnel is held' => [false, false, false,
        "    chain forward { type filter hook forward priority 0; iifname \"wg0\" ct state established,related accept; iifname \"wg0\" ip daddr 10.20.0.0/16 accept; iifname \"wg0\" drop; }\n"],
    'forward, connections in too' => [true, false, true,
        "    chain forward { type filter hook forward priority 0; iifname \"wg0\" ct state established,related accept; iifname \"wg0\" ip daddr 10.20.0.0/16 accept; iifname \"wg0\" drop; oifname \"wg0\" accept; }\n"],
    'NAT only: no IPv6 destination, so none is masqueraded' => [false, true, false,
        "    chain forward { type filter hook forward priority 0; iifname \"wg0\" ct state established,related accept; iifname \"wg0\" ip daddr 10.20.0.0/16 accept; iifname \"wg0\" drop; }\n"
        ."    chain postrouting { type nat hook postrouting priority 100; ip saddr 10.0.0.0/24 ip daddr 10.20.0.0/16 oifname \"eth0\" masquerade; }\n"],
]);

it('writes rules the real nft takes, and finds them again in what it lists', function (?string $address6, bool $forward, bool $nat, string $destinations) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', $forward, $nat, address6: $address6, destinations: $destinations));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    expect($box->run(['firewall-up', 'wg0', 'wg0'])['exit'])->toBe(0);

    $listed = listedByNft($box->stdin()[0], 'wg_wg0');
    if ($listed === null) {
        $this->markTestSkipped('No nft, or no network namespace to load rules into without root');
    }
    $box->respond('nft list table inet wg_wg0', $listed);

    // However this nft spells a network (host bits masked, a host without its mask, IPv6 shortened)
    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("ok\n", $listed);

    // And not when the config asks for other destinations than are installed
    $box->writeConf('wg0', appConf('Linux', $forward, $nat, address6: $address6, destinations: "{$destinations}, 198.51.100.0/24"));
    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("missing\n");
})->with([
    'both families, forward and NAT' => ['fd12:3456:789a::1/64', true, true, HELPER_DESTINATIONS.', fd00:0:0:1::7/128, 10.20.30.0/24'],
    'destinations alone' => [null, false, false, '10.20.0.0/16, 2001:db8::/32'],
    'NAT alone' => ['fd12:3456:789a::1/64', false, true, '192.0.2.50/32, fd00::/8'],
    'many' => [null, true, true, implode(', ', array_map(fn (int $n) => "10.{$n}.0.0/16", range(1, 120)))],
    'none' => ['fd12:3456:789a::1/64', true, true, '203.0.113.0/24'],
]);

it('finds the NAT rules of a link whose subnet is one address, which the tools list without its mask', function (?string $destinations) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', destinations: $destinations, address: '10.0.0.1/32'));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    expect($box->run(['firewall-up', 'wg0', 'wg0'])['exit'])->toBe(0);

    // As nft prints `ip saddr 10.0.0.1/32`: it was looked for with the mask, and missed every minute
    $scope = $destinations === null ? '' : ' ip daddr 10.20.0.0/16';
    $listed = "table inet wg_wg0 {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n"
        .($destinations === null ? "\t\tiifname \"wg0\" accept\n" : "\t\tiifname \"wg0\" ct state established,related accept\n\t\tiifname \"wg0\" ip daddr 10.20.0.0/16 accept\n\t\tiifname \"wg0\" drop\n")
        ."\t\toifname \"wg0\" ct state established,related accept\n\t\toifname \"wg0\" drop\n\t}\n\n"
        ."\tchain postrouting {\n\t\ttype nat hook postrouting priority srcnat; policy accept;\n\t\tip saddr 10.0.0.1{$scope} oifname \"eth0\" masquerade\n\t}\n}";
    $box->respond('nft list table inet wg_wg0', listedByNft($box->stdin()[0], 'wg_wg0') ?? $listed);

    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("ok\n");
    $box->respond('nft list table inet wg_wg0', $listed);
    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("ok\n");
})->with(['to anywhere' => [null], 'to its destinations' => ['10.20.0.0/16']]);

it('says whether a link with destinations has exactly the rules for them', function (string $listed, string $answer, ?string $destinations = HELPER_DESTINATIONS) {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', address6: 'fd12:3456:789a::1/64', destinations: $destinations));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');
    $box->respond('nft list table inet wg_wg0', $listed);

    expect($box->run(['firewall-check', 'wg0', 'wg0'])['stdout'])->toBe("{$answer}\n");
})->with([
    'all there, as nft prints them' => [NFT_LISTED_SCOPED, 'ok'],
    'the same networks spelled otherwise' => [str_replace(['10.20.0.0/16', '2001:db8:a::/48'], ['10.20.0.0/16', '2001:0db8:000A:0::/48'], NFT_LISTED_SCOPED), 'ok'],
    'a destination not forwarded to' => [str_replace("\t\tiifname \"wg0\" ip daddr 192.0.2.50 accept\n", '', NFT_LISTED_SCOPED), 'missing'],
    'one more than the config has' => [str_replace("\t\tiifname \"wg0\" drop\n", "\t\tiifname \"wg0\" ip daddr 198.51.100.0/24 accept\n\t\tiifname \"wg0\" drop\n", NFT_LISTED_SCOPED), 'missing'],
    'another network of the same size' => [str_replace('ip daddr 10.20.0.0/16 accept', 'ip daddr 10.21.0.0/16 accept', NFT_LISTED_SCOPED), 'missing'],
    'the same network, wider' => [str_replace('ip daddr 10.20.0.0/16 accept', 'ip daddr 10.20.0.0/15 accept', NFT_LISTED_SCOPED), 'missing'],
    'nothing dropped' => [str_replace("\t\tiifname \"wg0\" drop\n", '', NFT_LISTED_SCOPED), 'missing'],
    'everything accepted, from before it had destinations' => [str_replace("\t\tiifname \"wg0\" drop\n", "\t\tiifname \"wg0\" accept\n", NFT_LISTED_SCOPED), 'missing'],
    'replies to what came in not let out' => [str_replace("\t\tiifname \"wg0\" ct state established,related accept\n", '', NFT_LISTED_SCOPED), 'missing'],
    'a destination not masqueraded' => [str_replace("\t\tip saddr 10.0.0.0/24 ip daddr 192.0.2.50 oifname \"eth0\" masquerade\n", '', NFT_LISTED_SCOPED), 'missing'],
    'the IPv6 destination not masqueraded' => [str_replace("\t\tip6 saddr fd12:3456:789a::/64 ip6 daddr 2001:db8:a::/48 oifname \"eth0\" masquerade\n", '', NFT_LISTED_SCOPED), 'missing'],
    'everything masqueraded, from before it had destinations' => [str_replace("\t\tip saddr 10.0.0.0/24 ip daddr 192.0.2.50 oifname \"eth0\" masquerade\n", "\t\tip saddr 10.0.0.0/24 oifname \"eth0\" masquerade\n", NFT_LISTED_SCOPED), 'missing'],
    'masqueraded out of another interface' => [str_replace('oifname "eth0" masquerade', 'oifname "eth1" masquerade', NFT_LISTED_SCOPED), 'missing'],
    // The other way round: a link that has no destinations (any more) with the rules of one that has
    'rules for destinations the config no longer has' => [NFT_LISTED_SCOPED, 'missing', null],
    'the table gone' => ['', 'missing'],
]);

it('puts the rules of a link with destinations back when they are gone, and leaves them when they are there', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux', forward: false, nat: false, destinations: '10.20.0.0/16'));
    $box->writeConf('wg1', appConf('Linux', forward: false, nat: false, destinations: '10.20.0.0/16'));
    $box->respond('wg show interfaces', 'wg0 wg1');
    $box->respond('nft list table inet wg_wg0', '', 1);
    $box->respond('nft list table inet wg_wg1', "table inet wg_wg1 {\n\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tiifname \"wg1\" ct state established,related accept\n\t\tiifname \"wg1\" ip daddr 10.20.0.0/16 accept\n\t\tiifname \"wg1\" drop\n\t}\n}");

    $run = $box->run(['firewall-repair']);

    // The timer: a link with neither forward nor NAT has rules to lose too
    expect($run['stdout'])->toBe("<4>wgla-helper: link wg0 had lost its firewall rules; they are back\n")
        ->and($box->stdin())->toHaveCount(1)
        ->and($box->stdin()[0])->toContain('iifname "wg0" ip daddr 10.20.0.0/16 accept; iifname "wg0" drop;');
});

it('holds a link to its destinations on macOS, in what pf lets out and translates', function (bool $forward, bool $nat, string $rules) {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', $forward, $nat, address6: 'fd12:3456:789a::1/64', destinations: HELPER_DESTINATIONS));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    $run = $box->run(['firewall-up', 'wg0', 'utun5']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin()[0])->toBe($rules)->toBeAcceptedByPf();
})->with([
    // What comes in from the tunnel is tagged, and dropped where it would leave again: unless it
    // goes to a destination, which gives it another tag
    // (a tag per destination: rules that only differ in an address are what pfctl's optimizer folds into one)
    'forward and NAT' => [true, true,
        "nat on en0 from 10.0.0.0/24 to 10.20.0.0/16 -> (en0)\nnat on en0 from 10.0.0.0/24 to 192.0.2.50/32 -> (en0)\nnat on en0 inet6 from fd12:3456:789a::1/64 to 2001:db8:a::/48 -> (en0)\n"
        ."pass in on utun5 all no state tag wgla_no_wg0\npass in on utun5 inet from any to 10.20.0.0/16 tag wgla_to_wg0_1\npass in on utun5 inet from any to 192.0.2.50/32 tag wgla_to_wg0_2\n"
        ."pass in on utun5 inet6 from any to 2001:db8:a::/48 tag wgla_to_wg0_3\nblock drop out quick all tagged wgla_no_wg0\n"
        ."pass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\npass in on ! utun5 inet6 from any to fd12:3456:789a::1/64 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0\n"],
    'neither' => [false, false,
        "pass in on utun5 all no state tag wgla_no_wg0\npass in on utun5 inet from any to 10.20.0.0/16 tag wgla_to_wg0_1\npass in on utun5 inet from any to 192.0.2.50/32 tag wgla_to_wg0_2\n"
        ."pass in on utun5 inet6 from any to 2001:db8:a::/48 tag wgla_to_wg0_3\nblock drop out quick all tagged wgla_no_wg0\n"],
]);

it('drops what is not for a destination for good on macOS, whatever a link that takes connections in passes out', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', nat: false, inbound: true, destinations: '10.20.0.0/16'));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");

    $box->run(['firewall-up', 'wg0', 'utun5']);

    // pf goes by the last rule that matches: without `quick`, what one peer sends another (out of
    // the same utun) would match the drop and then this link's own `pass out`, and get through
    expect($box->stdin()[0])
        ->toBe("pass in on utun5 all no state tag wgla_no_wg0\npass in on utun5 inet from any to 10.20.0.0/16 tag wgla_to_wg0_1\nblock drop out quick all tagged wgla_no_wg0\npass out on utun5 all\n")
        ->toBeAcceptedByPf();
});

it('finds the rules for a link\'s destinations as pfctl prints them, and misses them when they are others', function (string $nat, string $rules, string $answer, ?string $destinations = HELPER_DESTINATIONS) {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', address6: 'fd12:3456:789a::1/64', destinations: $destinations));
    file_put_contents("{$box->runDir}/wg0.name", "utun5\n");
    $box->respond('pfctl -a wg/wg0 -s nat', $nat);
    $box->respond('pfctl -a wg/wg0 -s rules', $rules);

    expect($box->run(['firewall-check', 'wg0', 'utun5'])['stdout'])->toBe("{$answer}\n");
})->with(function () {
    // As pfctl prints them: a host without its mask, the prefix masked, state and flags spelled out
    $nat = "nat on en0 inet from 10.0.0.0/24 to 10.20.0.0/16 -> (en0) round-robin\nnat on en0 inet from 10.0.0.0/24 to 192.0.2.50 -> (en0) round-robin\nnat on en0 inet6 from fd12:3456:789a::/64 to 2001:db8:a::/48 -> (en0) round-robin";
    $rules = "pass in on utun5 all no state tag wgla_no_wg0\npass in on utun5 inet from any to 10.20.0.0/16 flags S/SA keep state tag wgla_to_wg0_1\npass in on utun5 inet from any to 192.0.2.50 flags S/SA keep state tag wgla_to_wg0_2\n"
        ."pass in on utun5 inet6 from any to 2001:db8:a::/48 flags S/SA keep state tag wgla_to_wg0_3\nblock drop out quick all tagged wgla_no_wg0\n"
        ."pass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\npass in on ! utun5 inet6 from any to fd12:3456:789a::/64 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0";
    $open = "pass in on utun5 all flags S/SA keep state\npass in on ! utun5 inet from any to 10.0.0.0/24 no state tag wgla_in_wg0\npass in on ! utun5 inet6 from any to fd12:3456:789a::/64 no state tag wgla_in_wg0\nblock drop out on utun5 all tagged wgla_in_wg0";

    return [
        'all there' => [$nat, $rules, 'ok'],
        'a destination not let out' => [$nat, str_replace("pass in on utun5 inet from any to 192.0.2.50 flags S/SA keep state tag wgla_to_wg0_2\n", '', $rules), 'missing'],
        'one more let out' => [$nat, str_replace('block drop out quick all', "pass in on utun5 inet from any to 198.51.100.0/24 flags S/SA keep state tag wgla_to_wg0_4\nblock drop out quick all", $rules), 'missing'],
        'nothing dropped on its way out' => [$nat, str_replace("block drop out quick all tagged wgla_no_wg0\n", '', $rules), 'missing'],
        // From before the drop was final: it could be passed out again further down
        'a drop that is not final' => [$nat, str_replace('block drop out quick all', 'block drop out all', $rules), 'missing'],
        'everything let in, from before it had destinations' => [$nat, "pass in on utun5 all flags S/SA keep state\n{$rules}", 'missing'],
        'a destination not translated' => [str_replace("nat on en0 inet from 10.0.0.0/24 to 192.0.2.50 -> (en0) round-robin\n", '', $nat), $rules, 'missing'],
        'everything translated' => ["nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin\n{$nat}", $rules, 'missing'],
        'rules for destinations the config no longer has' => ["nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin\nnat on en0 inet6 from fd12:3456:789a::/64 to any -> (en0) round-robin", $rules, 'missing', null],
        'no destinations, and none in the rules' => ["nat on en0 inet from 10.0.0.0/24 to any -> (en0) round-robin\nnat on en0 inet6 from fd12:3456:789a::/64 to any -> (en0) round-robin", $open, 'ok', null],
    ];
});

// ─── Adoption ───────────────────────────────────────────────────────

/** A config as the API before this one wrote it: hooks of its own, which the helper never takes from the app */
function foreignConf(): string
{
    return "[Interface]\nAddress = 10.0.42.1/24\nListenPort = 62990\nPrivateKey = ".HELPER_TEST_KEY."\n"
        ."PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -d 10.20.0.0/16 -o eth0 -j MASQUERADE;\n"
        ."PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -d 10.20.0.0/16 -o eth0 -j MASQUERADE;\n\n"
        ."[Peer]\nPublicKey = ".HELPER_TEST_KEY."\nAllowedIPs = 10.0.42.2/32\n";
}

it('says whether it would take a config, without writing it', function () {
    $box = new HelperSandbox;
    $box->writeConf('wg0', foreignConf());

    expect($box->run(['conf-check', 'wg0'], appConf('Linux'))['exit'])->toBe(0)
        ->and($box->run(['conf-check', 'wg1'], appConf('Linux'))['exit'])->toBe(0)
        ->and($box->run(['conf-check', 'wg0'], foreignConf())['stderr'])->toContain('PostUp must be exactly')
        ->and($box->run(['conf-check', '../etc'], appConf('Linux'))['stderr'])->toContain('invalid link name')
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe(foreignConf())
        ->and(array_values(array_diff(scandir($box->confDir), ['.', '..'])))->toBe(['wg0.conf'])
        ->and(glob("{$box->dir}/wgla.*"))->toBe([], 'No temp file is left behind')
        ->and($box->calls())->toBe([]);
});

it('replaces a config the app did not write with the app\'s, and keeps it until told the outcome', function (string $os) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', $legacy = foreignConf());
    chmod("{$box->confDir}/wg0.conf", 0640);
    $kept = "{$box->confDir}/.wg0.conf.before-adopt";

    $run = $box->run(['conf-adopt', 'wg0'], $new = appConf($os));

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($new)
        ->and(sprintf('%o', fileperms("{$box->confDir}/wg0.conf") & 0777))->toBe('600')
        ->and(file_get_contents($kept))->toBe($legacy)
        ->and(sprintf('%o', fileperms($kept) & 0777))->toBe('600')
        // The kept one is no link: not listed, not readable as one
        ->and($box->run(['conf-list'])['stdout'])->toBe("wg0\n");

    // The link didn't start: back to what was there, byte for byte
    expect($box->run(['conf-adopt-undo', 'wg0'])['exit'])->toBe(0)
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($legacy)
        ->and(file_exists($kept))->toBeFalse()
        ->and($box->run(['conf-adopt-undo', 'wg0'])['stderr'])->toContain('nothing to put back');

    // It did: nothing is kept
    $box->run(['conf-adopt', 'wg0'], $new);
    expect($box->run(['conf-adopt-done', 'wg0'])['exit'])->toBe(0)
        ->and(file_exists($kept))->toBeFalse()
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($new)
        ->and($box->run(['conf-adopt-done', 'wg0'])['exit'])->toBe(0, 'Nothing kept is nothing to do')
        ->and($box->calls())->toBe([]);
})->with('helper os');

it('only ever puts back what was there: it takes no config with hooks of its own, in an adoption either', function () {
    $box = new HelperSandbox;
    $box->writeConf('wg0', $legacy = foreignConf());

    // What it replaces a config with is checked like any config the app writes
    $run = $box->run(['conf-adopt', 'wg0'], str_replace('PostUp = ', 'PostUp = touch /tmp/pwned; ', appConf('Linux')));
    expect($run['exit'])->toBe(1)
        ->and($run['stderr'])->toContain('PostUp must be exactly')
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($legacy)
        ->and(array_values(array_diff(scandir($box->confDir), ['.', '..'])))->toBe(['wg0.conf'], 'Nothing kept, no temp file');

    // There is nothing to adopt where there is no config, and nothing to put back without an adoption
    expect($box->run(['conf-adopt', 'wg1'], appConf('Linux'))['exit'])->toBe(3)
        ->and($box->run(['conf-adopt-undo', 'wg0'])['exit'])->toBe(1)
        ->and($box->run(['conf-adopt', '../wg0'], appConf('Linux'))['stderr'])->toContain('invalid link name')
        ->and($box->run(['conf-adopt-undo', '.wg0'])['stderr'])->toContain('invalid link name')
        ->and(file_get_contents("{$box->confDir}/wg0.conf"))->toBe($legacy);

    // What is kept of a link goes with the link
    $box->run(['conf-adopt', 'wg0'], appConf('Linux'));
    $box->run(['conf-delete', 'wg0']);
    expect(array_values(array_diff(scandir($box->confDir), ['.', '..'])))->toBe([]);
});

it('tells whose private keys a link\'s client directory holds, by public key only', function () {
    $box = new HelperSandbox;
    $box->withPubkeys();
    $keys = new KeyManager;
    [$stored, $legacy, $indented, $loose] = [$keys->genkey(), $keys->genkey(), $keys->genkey(), $keys->genkey()];
    $box->run(['client-write', 'wg0', KeyManager::pubkeyToSafe($keys->pubkey($stored))], ConfigBuilder::clientKeyFile($stored)."\n");
    // As the API before this one kept them: a whole client config, named by the peer's address
    $box->writeClient('wg0', '10.0.42.2', "[Interface]\nPrivateKey = {$legacy}\nAddress    = 10.0.42.2/32\nDNS        = 8.8.8.8\n\n[Peer]\nPublicKey    = ".HELPER_TEST_KEY."\nAllowedIPs   = 10.20.0.0/16\n");
    $box->writeClient('wg0', '10.0.42.3', "[Interface]\n  PrivateKey=  {$indented}  \nAddress = 10.0.42.3/32\n");
    // As wg-quick itself would read one: the key name in any case, a comment after the key, CRLF
    $box->writeClient('wg0', '10.0.42.4', "[interface]\r\nprivatekey = {$loose} # the phone's\r\naddress = 10.0.42.4/32\r\n");
    $box->writeClient('wg0', 'notes', "nothing of a key in here\nPrivateKey = not-a-key\n");
    $box->writeClient('wg0', 'empty', '');
    symlink('/etc/hostname', "{$box->confDir}/clients/wg0/link.conf");
    $box->writeClient('wg1', '10.0.43.2', "[Interface]\nPrivateKey = {$keys->genkey()}\n");

    $run = $box->run(['client-keys', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toBe("stored {$keys->pubkey($stored)}\nlegacy {$keys->pubkey($legacy)}\nlegacy {$keys->pubkey($indented)}\nlegacy {$keys->pubkey($loose)}\n")
        ->and($run['stdout'].$run['stderr'])->not->toContain($stored)->not->toContain($legacy)->not->toContain($indented)->not->toContain($loose)
        ->and($box->run(['client-keys', 'wg9'])['stdout'])->toBe('', 'No client directory: no keys')
        ->and($box->run(['client-keys', '../wg0'])['stderr'])->toContain('invalid link name');
});

it('stores the keys an older API left the app\'s way, for the peers the link has and that have none', function () {
    $box = new HelperSandbox;
    $box->withPubkeys();
    $keys = new KeyManager;
    [$peer, $disabled, $stored, $stranger] = [$keys->genkey(), $keys->genkey(), $keys->genkey(), $keys->genkey()];
    $safe = fn (string $privkey) => KeyManager::pubkeyToSafe($keys->pubkey($privkey));
    $conf = (new ConfigBuilder([], new LinuxDriver(new FakeShell, HelperSandbox::path())))->buildConfFile('10.0.42.1/24', $keys->genkey(), 62990, 'eth0', [
        ['public_key' => $keys->pubkey($peer), 'allowed_ips' => '10.0.42.2/32'],
        ['public_key' => $keys->pubkey($disabled), 'allowed_ips' => '10.0.42.3/32', 'enabled' => false],
        ['public_key' => $keys->pubkey($stored), 'allowed_ips' => '10.0.42.4/32'],
        ['public_key' => $keys->pubkey($keys->genkey()), 'allowed_ips' => '10.0.42.5/32'], // a key of its own: no file of it
    ])."\n";
    $box->writeConf('wg0', $conf);
    $old = $box->writeClient('wg0', '10.0.42.2', "[Interface]\nPrivateKey = {$peer}\nAddress    = 10.0.42.2/32\n");
    $box->writeClient('wg0', '10.0.42.3', "[Interface]\nPrivateKey = {$disabled}\n");
    $box->writeClient('wg0', '10.0.42.4', "[Interface]\nPrivateKey = {$stored}\n");
    $box->writeClient('wg0', '10.0.42.2-copy', "[Interface]\nPrivateKey = {$peer}\n");
    $box->writeClient('wg0', '10.0.42.99', "[Interface]\nPrivateKey = {$stranger}\n"); // of a peer the link no longer has
    $box->run(['client-write', 'wg0', $safe($stored)], $own = ConfigBuilder::clientKeyFile($stored)."\n");

    $run = $box->run(['client-import', 'wg0']);

    // By public key, for the link's peers only (the disabled one too); never one that is stored
    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($run['stdout'])->toBe("{$keys->pubkey($peer)}\n{$keys->pubkey($disabled)}\n")
        ->and($run['stdout'].$run['stderr'])->not->toContain($peer)->not->toContain($disabled)
        ->and(ConfigBuilder::clientPrivateKey($box->run(['client-read', 'wg0', $safe($peer)])['stdout']))->toBe($peer)
        ->and(ConfigBuilder::clientPrivateKey($box->run(['client-read', 'wg0', $safe($disabled)])['stdout']))->toBe($disabled)
        ->and(sprintf('%o', fileperms("{$box->confDir}/clients/wg0/{$safe($peer)}.conf") & 0777))->toBe('600')
        ->and($box->run(['client-read', 'wg0', $safe($stored)])['stdout'])->toBe($own)
        ->and($box->run(['client-read', 'wg0', $safe($stranger)])['exit'])->toBe(3)
        // The old files stay as they were, and nothing else is left
        ->and(file_get_contents($old))->toBe("[Interface]\nPrivateKey = {$peer}\nAddress    = 10.0.42.2/32\n")
        ->and(glob("{$box->confDir}/clients/wg0/.wgla.*"))->toBe([])
        // Asked again, there is nothing left to do
        ->and($box->run(['client-import', 'wg0'])['stdout'])->toBe('')
        ->and($box->run(['client-keys', 'wg0'])['stdout'])->toContain("stored {$keys->pubkey($peer)}\n", "legacy {$keys->pubkey($peer)}\n", "legacy {$keys->pubkey($stranger)}\n")
        ->and($box->run(['client-import', 'wg9'])['exit'])->toBe(3, 'No config: no link to import for');
});
