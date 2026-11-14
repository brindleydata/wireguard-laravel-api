<?php

use App\Services\ConfigBuilder;
use App\Services\KeyManager;
use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use Tests\Fakes\FakeShell;
use Tests\Support\HelperSandbox;

/*
 * The root helper (bin/wgla-helper), run unprivileged against stub system commands and temp
 * directories. The configs come from the real drivers, so these tests also pin the contract
 * between the app and the helper.
 */

const HELPER_TEST_KEY = 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=';

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
function appConf(string $os, bool $forward = true, bool $nat = true, ?string $address6 = null): string
{
    $driver = $os === 'Darwin'
        ? new MacDriver(new FakeShell, HelperSandbox::path())
        : new LinuxDriver(new FakeShell, HelperSandbox::path());
    $keys = new KeyManager;

    return (new ConfigBuilder([], $driver))->buildConfFile(
        '10.0.0.1/24', $keys->genkey(), 51820, $os === 'Darwin' ? 'en0' : 'eth0',
        [
            ['public_key' => $keys->pubkey($keys->genkey()), 'preshared_key' => $keys->genpsk(), 'allowed_ips' => '10.0.0.2/32', 'name' => "Ана's phone (#2)"],
            ['public_key' => $keys->pubkey($keys->genkey()), 'allowed_ips' => '10.0.0.3/32, fd00::3/128, 192.168.1.0/24'],
            // Disabled: commented out, so wg-quick doesn't load it
            ['public_key' => $keys->pubkey($keys->genkey()), 'preshared_key' => $keys->genpsk(), 'allowed_ips' => '10.0.0.4/32', 'name' => 'old laptop', 'enabled' => false],
        ],
        '1.1.1.1, 8.8.8.8', 25, '0.0.0.0/0, ::/0', $forward, $nat, address6: $address6,
    )."\n";
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
        ->and($hooked)->toContain("[Peer]\n# name = Ана's phone (#2)\nPublicKey = ")->toContain("# [Peer] disabled\n# name = old laptop\n# PublicKey = ")
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
    'an Endpoint on the server' => ['/^\[Peer\]$/m', "[Peer]\nEndpoint = 203.0.113.1:51820", 'not allowed in a link config: Endpoint'],
    'shell syntax in metadata' => ['/^# ifout = .*$/m', '# ifout = eth0;id', 'metadata not allowed'],
    'shell syntax in an IPv6 address' => ['/^# address = .*$/m', "# address = 10.0.0.1/24\n# address6 = fd12::1/64;id", 'metadata not allowed'],
    'a second IPv6 address' => ['/^Address = .*$/m', 'Address = 10.0.0.1/24, fd12::1/64, fd13::1/64', 'not allowed in a link config: Address'],
    'an IPv6-only address' => ['/^Address = .*$/m', 'Address = fd12::1/64', 'not allowed in a link config: Address'],
    'a malformed IPv6 address' => ['/^Address = .*$/m', 'Address = 10.0.0.1/24, fd12:::1/64', 'not allowed in a link config: Address'],
    'unknown metadata' => ['/^/', "# owner = me\n", 'metadata not allowed'],
    'a comment after [Interface]' => ['/^\[Peer\]$/m', "# note\n[Peer]", 'comments are only allowed before [Interface]'],
    'a peer name in [Interface]' => ['/^ListenPort/m', "# name = me\nListenPort", 'comments are only allowed before [Interface]'],
    'a peer name before [Interface]' => ['/^/', "# name = me\n", 'metadata not allowed'],
    'a control character in a peer name' => ['/^# name = old laptop$/m', "# name = old\x1b[2Jlaptop", 'invalid peer name'],
    'an empty peer name' => ['/^# name = old laptop$/m', '# name = ', 'invalid peer name'],
    'a hook in a disabled peer' => ['/^# \[Peer\] disabled$/m', "# [Peer] disabled\n# PostUp = id", 'not allowed in a link config: PostUp = id'],
    'a bad key in a disabled peer' => ['/^(# PublicKey = ).*$/m', '$1not-a-key', 'not allowed in a link config: PublicKey = not-a-key'],
    'free text in a disabled peer' => ['/^# \[Peer\] disabled$/m', "# [Peer] disabled\n# remember to delete", 'malformed line in a disabled peer'],
    'a second [Interface]' => ['/\z/', "[Interface]\n", '[Interface] must come first, once'],
    'no [Interface]' => ['/\A[\s\S]*\z/', "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\n", '[Peer] before [Interface]'],
    'more than 1 MB' => ['/\z/', str_repeat("#\n", 600000), 'larger than'],
]);

it('lists only configs with valid link names', function () {
    $box = new HelperSandbox;
    foreach (['wg0.conf', 'bad name.conf', '.hidden.conf', 'notes.txt'] as $file) {
        touch("{$box->confDir}/{$file}");
    }

    expect($box->run(['conf-list'])['stdout'])->toBe("wg0\n");
});

// ─── Peers and client configs ───────────────────────────────────────

it('adds a validated peer to a running interface', function () {
    $box = new HelperSandbox;
    $peer = "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\nPresharedKey = ".HELPER_TEST_KEY."\nAllowedIPs = 10.0.0.2/32\n";

    expect($box->run(['peer-add', 'wg0'], $peer)['exit'])->toBe(0)
        ->and($box->calls())->toBe([['wg', 'addconf', 'wg0', '/dev/stdin']])
        ->and($box->stdin())->toBe([$peer]);
});

it('sets allowed IPs of both families in the form wg takes', function () {
    $box = new HelperSandbox;

    expect($box->run(['peer-ips', 'wg0', HELPER_TEST_KEY, '10.0.0.2/32, fd12::2/128'])['exit'])->toBe(0)
        ->and($box->calls())->toBe([['wg', 'set', 'wg0', 'peer', HELPER_TEST_KEY, 'allowed-ips', '10.0.0.2/32,fd12::2/128']]);
});

it('rejects a peer with anything but keys and allowed IPs', function (string $extra) {
    $box = new HelperSandbox;

    $run = $box->run(['peer-add', 'wg0'], "[Peer]\nPublicKey = ".HELPER_TEST_KEY."\n{$extra}\n");

    expect($run['exit'])->not->toBe(0)->and($box->calls())->toBe([]);
})->with([
    'an endpoint' => 'Endpoint = 203.0.113.1:51820',
    'a keepalive' => 'PersistentKeepalive = 25',
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

it('installs the link nftables table from its saved config', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux'));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');

    $run = $box->run(['firewall-up', 'wg0', 'wg0']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin())->toBe([<<<'NFT'
            table inet wg_wg0
            delete table inet wg_wg0
            table inet wg_wg0 {
                chain forward { type filter hook forward priority 0; iifname "wg0" accept; oifname "wg0" accept; }
                chain postrouting { type nat hook postrouting priority 100; ip saddr 10.0.0.0/24 oifname "eth0" masquerade; }
            }

            NFT])
        ->and(array_filter($box->calls(), fn ($call) => in_array('-I', $call, true)))->toBe([], 'Nothing in iptables drops forwarded traffic');
});

it('opens the iptables FORWARD chain when Docker or ufw drop forwarded traffic', function () {
    $box = new HelperSandbox('Linux');
    $box->writeConf('wg0', appConf('Linux'));
    $box->respond('iptables -S FORWARD', implode("\n", [
        // As real iptables prints them: the comment is quoted
        '-P FORWARD DROP',
        '-A FORWARD -i wg0 -m comment --comment "wgla:wg0" -j ACCEPT',
        '-A FORWARD -o wg0 -m comment --comment wgla:wg0 -j ACCEPT',
        '-A FORWARD -i wg01 -m comment --comment "wgla:wg01" -j ACCEPT',
        '-A FORWARD -j DOCKER-USER',
    ]));

    $box->run(['firewall-up', 'wg0', 'wg0']);

    expect(array_values(array_filter($box->calls(), fn ($call) => $call[0] === 'iptables' && $call[1] !== '-S')))->toBe([
        ['iptables', '-D', 'FORWARD', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-D', 'FORWARD', '-o', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-I', 'FORWARD', '1', '-o', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
        ['iptables', '-I', 'FORWARD', '1', '-i', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
    ]);
});

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
        ['ip6tables', '-I', 'FORWARD', '1', '-o', 'wg0', '-m', 'comment', '--comment', 'wgla:wg0', '-j', 'ACCEPT'],
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

it('loads nat before pass rules into the link pf anchor', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin'));

    $run = $box->run(['firewall-up', 'wg0', 'utun5']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->calls())->toBe([['pfctl', '-a', 'wg/wg0', '-f', '-'], ['pfctl', '-e']])
        ->and($box->stdin()[0])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\npass in on utun5 all\npass out on utun5 all\n")
        ->toBeAcceptedByPf();
});

it('adds an IPv6 nat rule to the pf anchor of a dual-stack link', function () {
    $box = new HelperSandbox('Darwin');
    $box->writeConf('wg0', appConf('Darwin', address6: 'fd12:3456:789a::1/64'));

    $run = $box->run(['firewall-up', 'wg0', 'utun5']);

    expect($run['exit'])->toBe(0, $run['stderr'])
        ->and($box->stdin()[0])
        ->toBe("nat on en0 from 10.0.0.0/24 to any -> (en0)\nnat on en0 inet6 from fd12:3456:789a::1/64 to any -> (en0)\n"
            ."pass in on utun5 all\npass out on utun5 all\n")
        ->toBeAcceptedByPf();
});

it('installs only the rules that are enabled', function (string $os, bool $forward, bool $nat) {
    $box = new HelperSandbox($os);
    $box->writeConf('wg0', appConf($os, $forward, $nat));
    $box->respond('iptables -S FORWARD', '-P FORWARD ACCEPT');

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

    $box->run(['firewall-up', 'wg0', 'wg0']);

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
