<?php

use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Installer;
use App\Setup\Steps\AppArmor;
use App\Setup\Steps\Environment;
use App\Setup\Steps\FirewallRepair;
use App\Setup\Steps\Forwarding;
use App\Setup\Steps\Health;
use App\Setup\Steps\Helper;
use App\Setup\Steps\Permissions;
use App\Setup\Steps\PfAnchors;
use App\Setup\Steps\Policy;
use App\Setup\Steps\Server;
use App\Setup\Steps\Shortcut;
use App\Setup\Steps\Sudoers;
use App\Setup\Steps\WebUser;
use App\Setup\Updater;
use Illuminate\Support\Sleep;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;
use Tests\Support\HelperSandbox;

/*
 * The installer steps against a temp app directory and a temp system root (for /etc/…).
 */

afterEach(function () {
    if (isset($this->tmp) && is_dir($this->tmp)) {
        exec('rm -rf '.escapeshellarg($this->tmp));
    }
    Sleep::fake(false);
});

/**
 * A context for a temp app (with .env.example and the real bundled helper) and a temp system root.
 */
function setupContext(string $os = 'linux', array $answers = []): Context
{
    $tmp = sys_get_temp_dir().'/wgla_setup_'.bin2hex(random_bytes(4));
    test()->tmp = $tmp;
    mkdir("{$tmp}/app/bin", 0755, true);
    mkdir("{$tmp}/root/etc", 0755, true);
    copy(HelperSandbox::path(), "{$tmp}/app/bin/wgla-helper");
    copy(dirname(HelperSandbox::path()).'/wgla', "{$tmp}/app/bin/wgla");
    file_put_contents("{$tmp}/app/.env.example", "APP_KEY=\nAPI_KEY=\n");

    return new Context(
        os: $os,
        appPath: "{$tmp}/app",
        deployUser: 'deploy',
        deployGroup: 'deploy',
        php: '/usr/bin/php',
        helperPath: "{$tmp}/root/usr/local/sbin/wgla-helper",
        bundledHelper: "{$tmp}/app/bin/wgla-helper",
        root: "{$tmp}/root",
        answers: ['web_user' => 'www-data', 'web_group' => 'www-data', ...$answers],
    );
}

// ─── .env ───────────────────────────────────────────────────────────

it('edits .env values in place and keeps everything else', function () {
    $ctx = setupContext();
    $env = new EnvFile($ctx->app('.env'));
    file_put_contents($env->path, "# comment\nAPP_NAME=\"WireGuard API\"\nAPI_KEY=\nOTHER=1\n");

    $env->set('API_KEY', 'abc123');
    $env->set('NEW_KEY', 'has spaces');
    $env->set('APP_NAME', 'Renamed');

    expect(file_get_contents($env->path))->toBe("# comment\nAPP_NAME=Renamed\nAPI_KEY=abc123\nOTHER=1\nNEW_KEY=\"has spaces\"\n")
        ->and($env->get('NEW_KEY'))->toBe('has spaces')
        ->and($env->get('MISSING'))->toBeNull()
        ->and(fn () => $env->set('X', "a\nb"))->toThrow(InvalidArgumentException::class);
});

it('reads back what it writes, as Laravel reads it, however often it is saved', function (string $value) {
    $ctx = setupContext();
    $env = new EnvFile($ctx->app('.env'));
    file_put_contents($env->path, "APP_NAME=x\n");

    $env->set('WGLA_SERVER_CERT', $value);
    $written = file_get_contents($env->path);
    // What the installer does on every run: read the answer, save it again
    $env->set('WGLA_SERVER_CERT', (string) $env->get('WGLA_SERVER_CERT'));

    expect($env->get('WGLA_SERVER_CERT'))->toBe($value)
        ->and(Dotenv\Dotenv::parse($written)['WGLA_SERVER_CERT'])->toBe($value, "Laravel's dotenv reads the same")
        ->and(file_get_contents($env->path))->toBe($written, 'Saved again, nothing changes');
})->with([
    'a plain path' => '/etc/ssl/api.pem',
    'spaces' => '/etc/ssl/my certs/api.pem',
    'backslashes' => 'C:\\certs\\api.pem',
    'a trailing backslash' => 'dir\\',
    'double quotes' => 'say "hi"',
    'a single quote' => "it's",
    'a dollar sign' => '/etc/ssl/$HOME/api.pem',
    'a variable reference' => '${APP_NAME}',
    'a hash' => 'cert #2',
    'escape-like text' => '\\n\\t\\$',
    'unicode' => '/etc/ssl/сертификат.pem',
    'empty' => '',
]);

it('reads values as Laravel does, however an admin wrote them', function (string $line, string $value) {
    $ctx = setupContext();
    $env = new EnvFile($ctx->app('.env'));
    file_put_contents($env->path, "APP_NAME=x\n{$line}\nOTHER=y\n");

    expect($env->get('API_KEY'))->toBe($value)
        ->and(Dotenv\Dotenv::parse((string) file_get_contents($env->path))['API_KEY'])->toBe($value, "Laravel's dotenv reads the same");

    // And a new value takes that line's place
    $env->set('API_KEY', 'new');
    expect($env->get('API_KEY'))->toBe('new')
        ->and(Dotenv\Dotenv::parse((string) file_get_contents($env->path))['API_KEY'])->toBe('new');
})->with([
    'a comment after the value' => ['API_KEY=abc123 # rotated in May', 'abc123'],
    'a comment after a tab' => ["API_KEY=abc123\t# note", 'abc123'],
    'double quotes with escapes' => ['API_KEY="a \\"b\\" \\\\ \\$c" # note', 'a "b" \\ $c'],
    'single quotes, taken literally' => ["API_KEY='a \\\"b\\\" \$c' # note", 'a \\"b\\" $c'],
    'spaces around =' => ['API_KEY = abc123', 'abc123'],
    'export' => ['export API_KEY=abc123', 'abc123'],
    'empty' => ['API_KEY=', ''],
    // As dotenv: the last line counts
    'twice' => ["API_KEY=old\nAPI_KEY=abc123", 'abc123'],
]);

it('reads .env values in shell scripts as Laravel does', function (string $script) {
    // The scripts that read .env without PHP: bin/wgla (sh), and update.sh (bash) on the server
    // it checks. A value cut at the = and stripped of quotes keeps its comment: WGLA_WEB_USER=x # y
    preg_match('/^env_value\(\) \{\n.*?^\}\n/ms', (string) file_get_contents(__DIR__.'/../../../'.$script), $function);
    expect($function)->not->toBe([], "{$script} has env_value()");
    $tmp = $this->tmp = sys_get_temp_dir().'/wgla_env_'.bin2hex(random_bytes(4));
    mkdir($tmp);
    file_put_contents("{$tmp}/env.sh", $function[0]);

    foreach ([
        'WGLA_WEB_USER=www-data', 'WGLA_WEB_USER=www-data # runs the API', "WGLA_WEB_USER=www-data\t# a tab", 'WGLA_WEB_USER=www-data#no space',
        'WGLA_WEB_USER="www-data" # quoted', "WGLA_WEB_USER='www-data' # single", 'WGLA_WEB_USER="a #b"', "WGLA_WEB_USER='a #b'",
        'WGLA_WEB_USER="a \\"b\\" \\\\ \\$c"', "WGLA_WEB_USER='a \\\"b\\\" \$c'", 'export WGLA_WEB_USER = www-data', '  WGLA_WEB_USER=www-data  ',
        'WGLA_WEB_USER=', 'WGLA_WEB_USER= # nothing', 'WGLA_WEB_USER=""', 'WGLA_WEB_USER=a=b', "WGLA_WEB_USER=old\nWGLA_WEB_USER=new",
        'WIREGUARD_HELPER=/usr/local/sbin/wgla-helper # installed', 'OTHER_WGLA_WEB_USER=no',
    ] as $line) {
        file_put_contents("{$tmp}/.env", "APP_NAME=x\n{$line}\nOTHER=y\n");
        $process = new Process([str_ends_with($script, '.sh') ? 'bash' : 'sh', '-c', '. ./env.sh; env_value WGLA_WEB_USER .env'], $tmp);
        $process->run();

        expect($process->getOutput())->toBe((Dotenv\Dotenv::parse((string) file_get_contents("{$tmp}/.env"))['WGLA_WEB_USER'] ?? '')."\n", $line);
    }
})->with(['bin/wgla', 'tests/e2e/update.sh']);

it('creates .env with fresh keys and makes it private', function (bool $separate) {
    $ctx = setupContext(answers: ['web_user' => $separate ? 'www-data' : 'deploy']);
    $step = new Environment((new FakeShell)->otherwise(fn () => throw new CommandFailed('not a git checkout')));

    expect($step->check($ctx))->toBe(['There is no .env file']);

    $plan = $step->plan($ctx);
    ($plan[0]->callback)($ctx);
    $env = new EnvFile($ctx->app('.env'));

    expect($env->get('APP_KEY'))->toStartWith('base64:')
        ->and($env->get('API_KEY'))->toMatch('/^[0-9a-f]{64}$/')
        ->and($env->get('OCTANE_SERVER'))->toBe('frankenphp')
        ->and($plan[1]->command)->toBe($separate
            ? "sudo chgrp 'www-data' '{$ctx->app('.env')}' && chmod 640 '{$ctx->app('.env')}'"
            : "chmod 600 '{$ctx->app('.env')}'");

    // Keys are kept on a re-run
    $key = $env->get('API_KEY');
    ($step->plan($ctx)[0]->callback)($ctx);
    expect($env->get('API_KEY'))->toBe($key);
})->with(['separate web user' => true, 'same user (macOS dev)' => false]);

it('asks nothing about where VPN clients connect: each link has that in its config', function () {
    $ctx = setupContext(answers: ['web_user' => 'deploy']);
    $step = new Environment((new FakeShell)->otherwise(fn () => throw new CommandFailed('not a git checkout')));
    $installer = new Installer((new FakeShell)->otherwise(fn () => 'deploy'), $ctx->helperPath);

    ($step->plan($ctx)[0]->callback)($ctx);
    $env = new EnvFile($ctx->app('.env'));

    expect($step->questions($ctx))->toBe([])
        ->and(file_get_contents($env->path))->not->toContain('WIREGUARD_HOSTNAME');

    // A server set up before has one in .env: nothing reads it, and it stays as it is
    $env->set('WIREGUARD_HOSTNAME', 'vpn.example.com');
    $saved = $installer->context([], $ctx->app(), $ctx->root);
    $installer->save($saved);

    expect($step->check($ctx))->toBe([])
        ->and($saved->answers)->not->toHaveKey('hostname')
        ->and($env->get('WIREGUARD_HOSTNAME'))->toBe('vpn.example.com');
});

it("offers the machine's name as the domain for Let's Encrypt, when it is one", function (string $name, ?string $domain) {
    $ctx = setupContext(answers: ['tls' => 'letsencrypt']);
    $server = new class(new FakeShell, $name) extends Server
    {
        public function __construct(FakeShell $shell, private string $name)
        {
            parent::__construct($shell);
        }

        protected function hostname(): string
        {
            return $this->name;
        }
    };

    expect(collect($server->questions($ctx))->firstWhere('key', 'domain')->defaultFor($ctx))->toBe($domain);

    // And with a certificate of one's own, the API's address has that name
    $ctx->answers = [...$ctx->answers, 'tls' => 'cert', 'port' => '8443'];
    expect($server->publicUrl($ctx))->toBe("https://{$name}:8443");
})->with([
    'a domain name' => ['vpn.example.com', 'vpn.example.com'],
    'an internationalized one' => ['vpn.xn--e1afmkfd.xn--p1ai', 'vpn.xn--e1afmkfd.xn--p1ai'],
    'a name of its own only' => ['vpn', null],
    'an IP address' => ['192.0.2.10', null],
]);

it('records the checked-out release as APP_VERSION', function () {
    $ctx = setupContext();
    $release = 'v1.2.0';
    $step = new Environment((new FakeShell)->on('git -C :app describe --tags --always --dirty', function () use (&$release) {
        return $release;
    }));
    ($step->plan($ctx)[0]->callback)($ctx);
    chmod($ctx->app('.env'), 0640);

    expect((new EnvFile($ctx->app('.env')))->get('APP_VERSION'))->toBe('v1.2.0')
        ->and($step->check($ctx))->not->toContain('APP_VERSION is not v1.2.0 (the checked-out release)');

    $release = 'v1.3.0';
    expect($step->check($ctx))->toContain('APP_VERSION is not v1.3.0 (the checked-out release)');
});

// ─── Helper and sudoers ─────────────────────────────────────────────

it('wants the bundled helper installed, owned by root', function () {
    $ctx = setupContext();
    $step = new Helper((new FakeShell)->otherwise(fn () => throw new CommandFailed));

    expect($step->check($ctx))->toBe(["The root helper is not installed at {$ctx->helperPath}"])
        ->and($step->plan($ctx)[0]->command)->toBe(
            "sudo mkdir -p '".dirname($ctx->helperPath)."' && sudo install -o root -g root -m 755 '{$ctx->bundledHelper}' '{$ctx->helperPath}'"
        );

    mkdir(dirname($ctx->helperPath), 0755, true);
    file_put_contents($ctx->helperPath, str_replace('VERSION='.helperVersion(), 'VERSION=0', file_get_contents($ctx->bundledHelper)));

    expect($step->check($ctx))->toContain("{$ctx->helperPath} differs from the bundled helper (installed v0, app v".helperVersion().')')
        // Owned by the test user, not root
        ->toContain("{$ctx->helperPath} must be owned by root and writable by nobody else");
});

it('shows what changes before replacing an installed helper', function () {
    $ctx = setupContext();
    mkdir(dirname($ctx->helperPath), 0755, true);
    copy($ctx->bundledHelper, $ctx->helperPath);
    $shell = (new FakeShell)->on('diff -u :installed :bundled || true', fn () => "-VERSION=0\n+VERSION=1");
    $step = new Helper($shell);

    expect($step->notice($ctx))->toBeNull('Identical: nothing to show');

    file_put_contents($ctx->helperPath, "#!/bin/bash\nVERSION=0\n");

    expect($step->notice($ctx))->toContain('Changes to the root helper (it runs as root)')->toContain('+VERSION=1');
});

it('installs the sudo rule only after visudo accepts it', function () {
    $ctx = setupContext();
    $shell = (new FakeShell)->on('sudo -n cat :file', fn () => 'www-data ALL=(root) NOPASSWD: /somewhere/else');
    $step = new Sudoers($shell);

    expect($step->line($ctx))->toBe("www-data ALL=(root) NOPASSWD: {$ctx->helperPath}")
        ->and($step->check($ctx))->toBe(['/etc/sudoers.d/wgla does not contain: '.$step->line($ctx)]);

    expect($step->plan($ctx)[0]->command)->toStartWith('(')->toEndWith('exit $status)');
});

it('never installs a sudo rule that visudo rejects', function (bool $valid) {
    $ctx = setupContext();
    $command = (new Sudoers(new FakeShell))->plan($ctx)[0]->command;

    // Run the planned command for real, with a stub sudo whose visudo accepts or rejects the file
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/sudo", "#!/bin/sh\necho \"\$*\" >> {$this->tmp}/sudo.log\n[ \"\$1\" = visudo ] && exit ".($valid ? 0 : 1)."\nexit 0\n");
    chmod("{$this->tmp}/bin/sudo", 0755);
    exec('PATH='.escapeshellarg("{$this->tmp}/bin").':/usr/bin:/bin sh -c '.escapeshellarg($command), result_code: $rc);
    $log = (string) file_get_contents("{$this->tmp}/sudo.log");

    expect($log)->toContain('visudo -cf')
        ->and($rc === 0)->toBe($valid)
        ->and(str_contains($log, 'install -o root'))->toBe($valid);
})->with(['accepted' => true, 'rejected' => false]);

// ─── Route policy ───────────────────────────────────────────────────

it('writes what peers may route to a file of root\'s, right after the sudo rule', function (array $answers, string $content) {
    $ctx = setupContext(answers: $answers);
    $step = new Policy(new FakeShell);
    $keys = array_map(fn ($step) => $step->key(), (new Installer(new FakeShell))->steps());

    expect($step->applies($ctx))->toBeTrue()
        ->and($step->applies(new Context('mac', $ctx->appPath, 'deploy', 'staff', '/usr/bin/php', $ctx->helperPath, $ctx->bundledHelper)))->toBeTrue()
        ->and(array_search('policy', $keys, true))->toBe(array_search('sudoers', $keys, true) + 1)
        ->and(array_map(fn ($question) => [$question->key, $question->type, $question->defaultFor($ctx)], $step->questions($ctx)))
        ->toBe([['allow_default_route', 'confirm', false], ['allow_own_networks', 'confirm', false]])
        ->and($step->content($ctx))->toBe($content)
        ->and($step->check($ctx))->toBe(['/etc/wgla/policy.conf is missing or out of date']);

    // The planned command for real, with a sudo that runs it as us, minus the owner (root)
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/sudo", "#!/bin/sh\necho \"\$*\" >> {$this->tmp}/sudo.log\n"
        ."skip=; for a do shift; if [ -n \"\$skip\" ]; then skip=; elif [ \"\$a\" = -o ] || [ \"\$a\" = -g ]; then skip=1; else set -- \"\$@\" \"\$a\"; fi; done\nexec \"\$@\"\n");
    chmod("{$this->tmp}/bin/sudo", 0755);
    $process = Process::fromShellCommandline($step->plan($ctx)[0]->command, env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin"]);
    $process->run();
    $file = $ctx->system(Policy::FILE);

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and(file_get_contents("{$this->tmp}/sudo.log"))->toContain('install -d -o root -g root -m 755 '.dirname($file)."\n", 'install -o root -g root -m 644 /', " {$file}\n")
        ->and(file_get_contents($file))->toBe($content)
        ->and(sprintf('%o %o', fileperms($file) & 0777, fileperms(dirname($file)) & 0777))->toBe('644 755')
        // Not root's here
        ->and($step->check($ctx))->toBe(['/etc/wgla/policy.conf and its directory must be owned by root and writable by nobody else']);

    // Another answer: another file
    $ctx->answers['allow_own_networks'] = ! filter_var($answers['allow_own_networks'] ?? false, FILTER_VALIDATE_BOOLEAN);
    expect($step->check($ctx))->toBe(['/etc/wgla/policy.conf is missing or out of date']);
})->with([
    'nothing answered: neither' => [[], "# Written by php artisan wg:install: what peers of any link may route (the root helper enforces it)\nallow_default_route=false\nallow_own_networks=false\n"],
    'answered' => [['allow_default_route' => true, 'allow_own_networks' => false], "# Written by php artisan wg:install: what peers of any link may route (the root helper enforces it)\nallow_default_route=true\nallow_own_networks=false\n"],
    // As .env has them, for a re-run or an update
    'saved' => [['allow_default_route' => 'false', 'allow_own_networks' => 'true'], "# Written by php artisan wg:install: what peers of any link may route (the root helper enforces it)\nallow_default_route=false\nallow_own_networks=true\n"],
]);

it('writes the policy with macOS\'s root group, and its install, which has no -D', function () {
    $command = (new Policy(new FakeShell))->plan($ctx = setupContext('mac'))[0]->command;

    expect($command)->toContain("sudo install -d -o root -g wheel -m 755 '".dirname($ctx->system(Policy::FILE))."'")
        ->toContain("sudo install -o root -g wheel -m 644 \"\$tmp\" '{$ctx->system(Policy::FILE)}'")
        ->not->toContain(' -D ')
        ->toStartWith('(')->toEndWith('exit $status)');
});

// ─── IP forwarding and pf ───────────────────────────────────────────

/** A Linux host's forwarding state: null for IPv6 means the kernel has no IPv6. */
function forwardingShell(string $ipv4, ?string $ipv6, ?string $acceptRa = null): FakeShell
{
    return (new FakeShell)
        ->on('sysctl -n net.ipv4.ip_forward', fn () => $ipv4)
        ->on('sysctl -n net.ipv6.conf.all.forwarding', fn () => $ipv6 ?? throw new CommandFailed('sysctl: cannot stat /proc/sys/net/ipv6'))
        ->on('ip -6 route show default', fn () => $acceptRa === null ? '' : 'default via fe80::1 dev eth0 proto ra metric 100 expires 1795sec pref medium')
        ->on('cat :file', fn (array $b) => $b['file'] === '/proc/sys/net/ipv6/conf/eth0/accept_ra' ? $acceptRa : throw new CommandFailed('No such file'));
}

it('turns IP forwarding on persistently on Linux, only when links route traffic', function () {
    $ctx = setupContext(answers: ['forward' => true]);
    $step = new Forwarding(forwardingShell('0', null));

    expect($step->check($ctx))->toBe(['IP forwarding is off', 'IP forwarding is not kept across reboots'])
        ->and($step->plan($ctx)[0]->command)->toBe("printf '%s\\n' 'net.ipv4.ip_forward=1' | sudo tee '{$ctx->system('/etc/sysctl.d/99-wireguard.conf')}' > /dev/null && sudo sysctl --system > /dev/null");

    $ctx->answers['forward'] = false;
    expect($step->check($ctx))->toBe([]);
});

it('turns IPv6 forwarding on too where the kernel has IPv6', function () {
    $ctx = setupContext(answers: ['forward' => true]);
    mkdir($ctx->system('/etc/sysctl.d'));
    file_put_contents($ctx->system('/etc/sysctl.d/99-wireguard.conf'), "net.ipv4.ip_forward=1\n");

    // The IPv6 route comes from router advertisements that systemd-networkd handles (accept_ra 0)
    $step = new Forwarding(forwardingShell('1', '0', acceptRa: '0'));

    expect($step->check($ctx))->toBe(['IPv6 forwarding is off', 'IPv6 forwarding is not kept across reboots'])
        ->and($step->plan($ctx)[0]->command)->toStartWith("printf '%s\\n' 'net.ipv4.ip_forward=1' 'net.ipv6.conf.all.forwarding=1' | sudo tee");

    file_put_contents($ctx->system('/etc/sysctl.d/99-wireguard.conf'), "net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n");
    expect((new Forwarding(forwardingShell('1', '1', acceptRa: '0')))->check($ctx))->toBe([]);
});

it('keeps router advertisements on the IPv6 uplink where the kernel handles them', function () {
    $ctx = setupContext(answers: ['forward' => true]);
    mkdir($ctx->system('/etc/sysctl.d'));
    $step = new Forwarding(forwardingShell('1', '0', acceptRa: '1'));

    expect($step->check($ctx))->toContain('eth0 learns its IPv6 route from router advertisements, which IPv6 forwarding would turn off')
        ->and($step->plan($ctx)[0]->command)->toContain("'net.ipv6.conf.all.forwarding=1' 'net/ipv6/conf/eth0/accept_ra=2' | sudo tee");

    // Applied: accept_ra is 2 now, and later plans keep the line
    file_put_contents($ctx->system('/etc/sysctl.d/99-wireguard.conf'), "net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\nnet/ipv6/conf/eth0/accept_ra=2\n");
    $applied = new Forwarding(forwardingShell('1', '1', acceptRa: '2'));
    expect($applied->check($ctx))->toBe([])
        ->and($applied->plan($ctx)[0]->command)->toContain("'net/ipv6/conf/eth0/accept_ra=2'");
});

it('turns IPv6 forwarding on with IPv4 on macOS', function () {
    $ctx = setupContext('mac', answers: ['forward' => true]);
    $step = new Forwarding((new FakeShell)
        ->on('sysctl -n net.inet.ip.forwarding', fn () => '0')
        ->on('sysctl -n net.inet6.ip6.forwarding', fn () => '0'));

    expect($step->check($ctx))->toBe(['IP forwarding is off', 'IPv6 forwarding is off'])
        ->and($step->plan($ctx)[0]->command)->toBe('sudo sysctl -w net.inet.ip.forwarding=1 net.inet6.ip6.forwarding=1');
});

it('adds the pf anchors where pf accepts them, also repairing the old appended ones', function (string $pfConf) {
    if (! is_executable('/sbin/pfctl')) {
        $this->markTestSkipped('needs pfctl (macOS) to validate the result');
    }
    $ctx = setupContext('mac');
    $conf = $ctx->system('/etc/pf.conf');
    file_put_contents($conf, $pfConf);
    $shell = (new FakeShell)->on('pfctl -n -f :file', fn (array $b) => exec('/sbin/pfctl -n -f '.escapeshellarg($b['file']).' 2>/dev/null', result_code: $rc) !== false && $rc === 0 ? '' : throw new CommandFailed);
    $step = new PfAnchors($shell);

    expect($step->check($ctx))->not->toBe([]);

    // Run the planned command for real, minus the sudo parts (they install into the temp root)
    $command = str_replace(['sudo install -o root -g wheel -m 644', 'sudo cp', 'sudo pfctl -f'], ['install -m 644', 'cp', 'true'], $step->plan($ctx)[0]->command);
    exec($command, result_code: $rc);

    expect($rc)->toBe(0)
        ->and($step->check($ctx))->toBe([])
        ->and(substr_count(file_get_contents($conf), 'anchor "wg/*"'))->toBe(2)
        ->and(file_get_contents($conf))->not->toContain('# WireGuard NAT anchors')
        ->and($ctx->system('/etc/pf.conf.wgla-backup'))->toBeFile();
})->with([
    'stock macOS pf.conf' => implode("\n", ['scrub-anchor "com.apple/*"', 'nat-anchor "com.apple/*"', 'rdr-anchor "com.apple/*"', 'dummynet-anchor "com.apple/*"', 'anchor "com.apple/*"', 'load anchor "com.apple" from "/etc/pf.anchors/com.apple"', '']),
    'appended by the old instructions' => implode("\n", ['scrub-anchor "com.apple/*"', 'nat-anchor "com.apple/*"', 'rdr-anchor "com.apple/*"', 'dummynet-anchor "com.apple/*"', 'anchor "com.apple/*"', 'load anchor "com.apple" from "/etc/pf.anchors/com.apple"', '', '# WireGuard NAT anchors', 'nat-anchor "wg/*"', 'anchor "wg/*"', '']),
]);

// ─── File ownership ─────────────────────────────────────────────────

/** The command that lists what the web user can change in the app (Permissions::changeable()). */
const CHANGEABLE = 'sudo -n find :app -path :storage -prune -o ! -type l \( -user :user -print -o -exec sudo -n -u :user sh -c :test sh {} + \)';

it('keeps the code, bootstrap/cache included, read-only for the web user', function () {
    $ctx = setupContext();
    mkdir($ctx->app('bootstrap/cache'), 0755, true);
    mkdir($ctx->app('app'));
    // The web user can write everything: a wrong ownership to fix
    $everything = array_map(fn (string $path) => $ctx->app($path), ['', 'app', 'artisan', 'bin', 'bin/wgla', 'bin/wgla-helper', 'bootstrap', 'bootstrap/cache', 'frankenphp']);
    $shell = (new FakeShell)
        ->on('sudo -n -u :user test -w :path', fn () => '')
        ->on('sudo -n -u :user test -r :path', fn () => '')
        ->on(CHANGEABLE, fn (array $b) => $b['user'] === 'www-data' && $b['storage'] === $ctx->app('storage') ? implode("\n", array_reverse($everything)) : throw new CommandFailed);
    $step = new Permissions($shell);

    expect($step->check($ctx))->toBe(['www-data can change the code: the app directory, app/, artisan, bin/, bin/wgla and 4 more']);

    [$code, $storage] = $step->plan($ctx);
    expect($code->command)->toBe("sudo chown -R 'deploy:deploy' '{$ctx->app()}' && sudo chmod -R go-w '{$ctx->app()}'")
        ->and($storage->command)->toContain("sudo chown -R 'www-data:www-data' '{$ctx->app('storage')}' &&")
        ->and($storage->command)->not->toContain('bootstrap/cache');

    // Fixed: nothing but storage/
    $shell->on(CHANGEABLE, fn () => '');
    expect($step->check($ctx))->toBe([]);

    // Not known is not fine
    $shell->on(CHANGEABLE, fn () => throw new CommandFailed('sudo: a password is required'));
    expect($step->check($ctx))->toBe(["It can't be told what www-data can change in the app"]);
});

it('finds every file outside storage/ that the web user can change, not only directories', function (bool $owner, array $expected) {
    if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
        $this->markTestSkipped('root can write anything');
    }
    $ctx = setupContext();
    $app = $ctx->app();
    // As wg:install leaves it (read-only), but for what each case makes writable
    foreach (['app', 'bootstrap/cache', 'deploy', '.git/hooks', 'storage/logs'] as $dir) {
        mkdir("{$app}/{$dir}", 0755, true);
    }
    foreach (['artisan', 'frankenphp', 'app/Thing.php', 'deploy/Caddyfile', '.git/hooks/post-checkout', 'storage/logs/laravel.log', '.env'] as $file) {
        file_put_contents("{$app}/{$file}", '');
    }
    symlink('storage/logs', "{$app}/logs"); // a symlink: its target is what counts
    exec('chmod -R a-w '.escapeshellarg($app));
    chmod("{$app}/frankenphp", 0755);
    chmod("{$app}/.git/hooks/post-checkout", 0755);
    chmod("{$app}/.git/hooks", 0755);
    chmod("{$app}/storage", 0755);
    chmod("{$app}/storage/logs", 0755);

    // The real command, with a sudo that runs it as us. Owner: the web user is us, who owns all
    // of it (and could make anything writable); else root, who owns none of it here.
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/sudo", "#!/bin/sh\nwhile [ \$# -gt 0 ]; do case \$1 in -u) shift 2 ;; -*) shift ;; *) break ;; esac; done\nexec \"\$@\"\n");
    chmod("{$this->tmp}/bin/sudo", 0755);
    $shell = (new FakeShell)->on(CHANGEABLE, function () use (&$shell) {
        $process = Process::fromShellCommandline(end($shell->calls)['bound'], env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin"]);
        $process->run();

        return $process->isSuccessful() ? $process->getOutput() : throw new CommandFailed($process->getErrorOutput());
    });
    $ctx->answers['web_user'] = $owner ? trim((string) shell_exec('id -un')) : 'root';
    $step = new class($shell) extends Permissions
    {
        public function changeable(Context $ctx): ?array
        {
            return parent::changeable($ctx);
        }
    };

    try {
        expect($step->changeable($ctx))->toBe($expected);
    } finally {
        exec('chmod -R u+w '.escapeshellarg($app));
    }
})->with([
    'what it can write' => [false, ['.git/hooks/', '.git/hooks/post-checkout', 'frankenphp']],
    'what it owns, writable or not' => [true, ['the app directory', '.env', '.env.example', '.git/', '.git/hooks/', '.git/hooks/post-checkout', 'app/', 'app/Thing.php',
        'artisan', 'bin/', 'bin/wgla', 'bin/wgla-helper', 'bootstrap/', 'bootstrap/cache/', 'deploy/', 'deploy/Caddyfile', 'frankenphp']],
]);

it('only applies when the API runs as its own user', function () {
    expect((new Permissions(new FakeShell))->applies(setupContext()))->toBeTrue()
        ->and((new Permissions(new FakeShell))->applies(setupContext(answers: ['web_user' => 'deploy'])))->toBeFalse();
});

// ─── wgla ───────────────────────────────────────────────────────────

it('installs the wgla shortcut root-owned, and again when it changes', function () {
    $ctx = setupContext();
    $step = new Shortcut(new FakeShell);

    expect($step->check($ctx))->toBe(['/usr/local/bin/wgla is missing or out of date'])
        ->and($step->plan($ctx)[0]->command)->toContain("sudo install -o root -g root -m 755 \"\$tmp\" '{$ctx->system('/usr/local/bin/wgla')}'");

    mkdir(dirname($ctx->system(Shortcut::FILE)), 0755, true);
    file_put_contents($ctx->system(Shortcut::FILE), $step->script($ctx));
    expect($step->check($ctx))->toBe([]);

    $ctx->answers['web_user'] = 'nginx';
    expect($step->check($ctx))->not->toBe([], 'Another web user: a new script')
        ->and($step->script($ctx))->toContain("WEB='nginx'\n", "APP='{$ctx->app()}'\n")->not->toMatch('/@[A-Z]+@/');
});

it('runs each wgla command as the user it belongs to', function (array $args, array $env, string $expected) {
    $ctx = setupContext();
    mkdir("{$this->tmp}/bin");
    foreach (['sudo', 'php', 'composer'] as $stub) {
        // Each prints its argv (a line each); php lists commands as `artisan list wg --raw` does,
        // and sudo runs the check for an unfinished update for real, as the user it is given
        $list = match ($stub) {
            'php' => "[ \"\$2\" = list ] && { printf 'wg:links         List WireGuard links\\nwg:link:create   Create a WireGuard link\\n'; exit; }\n",
            'sudo' => "[ \"\$5\" = sh ] && { shift 4; exec \"\$@\"; }\n",
            default => '',
        };
        file_put_contents("{$this->tmp}/bin/{$stub}", "#!/bin/sh\n{$list}printf '%s' {$stub}; for a in \"\$@\"; do printf ' [%s]' \"\$a\"; done; echo\n");
        chmod("{$this->tmp}/bin/{$stub}", 0755);
    }
    // Where git keeps wg:update's record of an update in progress (relative to the app)
    file_put_contents("{$this->tmp}/bin/git", "#!/bin/sh\n[ \"\$*\" = 'rev-parse --git-path wgla-update' ] && echo .git/wgla-update\n");
    chmod("{$this->tmp}/bin/git", 0755);
    if ($env['RECORD'] ?? false) {
        mkdir($ctx->app('.git'));
        file_put_contents($ctx->app('.git/wgla-update'), '{"from":"aaa111","to":"bbb222","frankenphp":null}');
    }
    // php is the stub; the web user is whoever runs the test when the case asks for it
    $me = trim((string) shell_exec('id -un'));
    $ctx = new Context(os: 'linux', appPath: $ctx->appPath, deployUser: 'deploy', deployGroup: 'deploy', php: "{$this->tmp}/bin/php",
        helperPath: $ctx->helperPath, bundledHelper: $ctx->bundledHelper, root: $ctx->root,
        answers: ['web_user' => ($env['AS_WEB'] ?? false) ? $me : 'www-data', 'web_group' => 'www-data']);
    file_put_contents("{$this->tmp}/wgla", (new Shortcut(new FakeShell))->script($ctx));
    chmod("{$this->tmp}/wgla", 0755);

    $process = new Process(["{$this->tmp}/wgla", ...$args], env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin", ...array_diff_key($env, ['AS_WEB' => 1, 'RECORD' => 1])]);
    $process->run();

    expect(trim($process->getOutput()))->toBe(strtr($expected, ['PHP' => "{$this->tmp}/bin/php", 'ARTISAN' => "{$ctx->app()}/artisan", 'APP' => $ctx->app()]), $process->getErrorOutput());
})->with([
    'no command: the commands, as wgla takes them' => [[], [], "Usage: wgla <command> [arguments] [options]\n\n  links         List WireGuard links\n  link:create   Create a WireGuard link\n\nwgla help <command> shows its arguments and options."],
    'a link command' => [['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]'],
    'arguments as given' => [['wg:peer:create', 'wg0', "--name=Ана's phone"], [], "sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:peer:create] [wg0] [--name=Ана's phone]"],
    'install and update' => [['update', '--to=v1.2.0'], [], 'sudo [-H] [-u] [deploy] [--] [PHP] [ARTISAN] [wg:update] [--to=v1.2.0]'],
    // It may have left vendor/ unable to boot artisan, which has to go back
    'update after one that never ended: its dependencies first' => [['update'], ['RECORD' => true],
        "sudo [-H] [-u] [deploy] [--] [composer] [install] [--no-dev] [--optimize-autoloader] [--no-interaction] [--working-dir=APP]\nsudo [-H] [-u] [deploy] [--] [PHP] [ARTISAN] [wg:update]"],
    '... but no other command' => [['install'], ['RECORD' => true], 'sudo [-H] [-u] [deploy] [--] [PHP] [ARTISAN] [wg:install]'],
    'help, as whoever asks' => [['help'], [], 'php [ARTISAN] [wg:help]'],
    "a command's help" => [['help', 'peer:create'], [], 'php [ARTISAN] [help] [wg:peer:create]'],
    'a backup passphrase' => [['backup'], ['WGLA_BACKUP_PASSPHRASE' => 'secret phrase'], 'sudo [-H] [-u] [www-data] [--preserve-env=WGLA_BACKUP_PASSPHRASE] [--] [PHP] [ARTISAN] [wg:backup]'],
    'already the web user: no sudo' => [['links'], ['AS_WEB' => true], 'php [ARTISAN] [wg:links]'],
]);

it('runs bin/wgla as is from a checkout: this project, the shell\'s php, users from .env and the owner', function (string $dotenv, array $args, array $env, string $expected, bool $symlink) {
    setupContext();
    $app = "{$this->tmp}/checkout";
    mkdir("{$app}/bin", 0755, true);
    copy(dirname(HelperSandbox::path()).'/wgla', "{$app}/bin/wgla");
    chmod("{$app}/bin/wgla", 0755);
    // INSTALLED: a helper path that exists, as after wg:install (the default may or may not here)
    file_put_contents("{$app}/.env", strtr($dotenv, ['INSTALLED' => "{$app}/bin/wgla"]));
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/php", "#!/bin/sh\nprintf php; [ -z \"\$WIREGUARD_HELPER\" ] || printf ' {helper=%s}' \"\$WIREGUARD_HELPER\"\n"
        ."[ \"\$2\" = list ] && { printf '\\nwg:links         List WireGuard links\\n'; exit; }\nfor a in \"\$@\"; do printf ' [%s]' \"\$a\"; done; echo\n");
    // sudo -n fails when a password is needed (SUDO_NEEDS_PASSWORD)
    file_put_contents("{$this->tmp}/bin/sudo", "#!/bin/sh\nprintf sudo; for a in \"\$@\"; do printf ' [%s]' \"\$a\"; done; echo\n"
        ."[ \"\$1\" = -n ] && [ -n \"\$SUDO_NEEDS_PASSWORD\" ] && exit 1; exit 0\n");
    file_put_contents("{$this->tmp}/bin/composer", "#!/bin/sh\nprintf composer; for a in \"\$@\"; do printf ' [%s]' \"\$a\"; done; echo\n");
    file_put_contents("{$this->tmp}/bin/git", "#!/bin/sh\n[ \"\$*\" = 'rev-parse --git-path wgla-update' ] && echo .git/wgla-update\n");
    foreach (['php', 'sudo', 'composer', 'git'] as $stub) {
        chmod("{$this->tmp}/bin/{$stub}", 0755);
    }
    if ($env['RECORD'] ?? false) {
        mkdir("{$app}/.git");
        file_put_contents("{$app}/.git/wgla-update", '{"from":"aaa111","to":"bbb222","frankenphp":null}');
    }
    // Run through a relative symlink elsewhere, as when it's linked into the PATH
    $command = "{$app}/bin/wgla";
    if ($symlink) {
        mkdir("{$this->tmp}/links");
        symlink('../checkout/bin/wgla', $command = "{$this->tmp}/links/wgla");
    }

    $process = new Process([$command, ...$args], env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin", ...array_diff_key($env, ['RECORD' => 1])]);
    $process->run();

    expect(trim($process->getOutput()))->toBe(strtr($expected, [
        'PHP' => "{$this->tmp}/bin/php", 'ARTISAN' => realpath($app).'/artisan', 'BESIDE' => realpath($app).'/bin/wgla-helper', 'APP' => realpath($app),
    ]), $process->getErrorOutput());
})->with([
    'the web user from .env' => ["WGLA_WEB_USER=\"www-data\"\nWIREGUARD_HELPER=INSTALLED\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', false],
    // Read as Laravel reads them, not cut at the = and stripped of quotes
    'the web user with a comment' => ["WGLA_WEB_USER=www-data # runs the API\nWIREGUARD_HELPER=INSTALLED # by wg:install\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', false],
    '... quoted, with export and spaces' => ["export WGLA_WEB_USER = 'www-data' # x\nWIREGUARD_HELPER=\"INSTALLED\"\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', false],
    '... the last one' => ["WGLA_WEB_USER=nobody\nWGLA_WEB_USER=www-data\nWIREGUARD_HELPER=INSTALLED\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', false],
    'update after one that never ended, as the owner: its dependencies first' => ["WGLA_WEB_USER=www-data\n", ['update'], ['RECORD' => true],
        "composer [install] [--no-dev] [--optimize-autoloader] [--no-interaction] [--working-dir=APP]\nphp [ARTISAN] [wg:update]", false],
    'no web user in .env: the API runs as you' => ["WIREGUARD_HELPER=INSTALLED\n", ['links'], [], 'php [ARTISAN] [wg:links]', false],
    'update as the owner of the project (you)' => ["WGLA_WEB_USER=www-data\n", ['update'], [], 'php [ARTISAN] [wg:update]', false],
    'through a symlink' => ["WGLA_WEB_USER=www-data\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', true],
    'no helper installed: the one beside it, through your sudo' => ["WIREGUARD_HELPER=/nowhere/wgla-helper\n", ['links'], [], "sudo [-n] [true]\nphp {helper=BESIDE} [ARTISAN] [wg:links]", false],
    '... asking for your password once' => ["WIREGUARD_HELPER=/nowhere/wgla-helper\n", ['links'], ['SUDO_NEEDS_PASSWORD' => '1'], "sudo [-n] [true]\nsudo [-v]\nphp {helper=BESIDE} [ARTISAN] [wg:links]", false],
    '... but never for install, which would make it the installed one' => ["WIREGUARD_HELPER=/nowhere/wgla-helper\n", ['install'], [], 'php [ARTISAN] [wg:install]', false],
    '... nor to list the commands' => ["WIREGUARD_HELPER=/nowhere/wgla-helper\n", [], [], "Usage: wgla <command> [arguments] [options]\n\nphp\n  links         List WireGuard links\n\nwgla help <command> shows its arguments and options.", false],
]);

// ─── AppArmor ───────────────────────────────────────────────────────

it('lets wg-quick run the helper where Ubuntu confines it with AppArmor', function () {
    $ctx = setupContext();
    $step = new AppArmor(new FakeShell);
    expect($step->applies($ctx))->toBeFalse('No wg-quick profile, nothing to do');

    mkdir($ctx->system('/etc/apparmor.d/local'), 0755, true);
    touch($ctx->system('/etc/apparmor.d/wg-quick'));
    file_put_contents($ctx->system('/etc/apparmor.d/local/wg-quick'), "# the admin's own rule\n/usr/bin/foo ix,\n");

    expect($step->applies($ctx))->toBeTrue()
        ->and($step->applies(setupContext('mac')))->toBeFalse()
        ->and($step->check($ctx))->toBe(["AppArmor doesn't let wg-quick run the root helper: links with forward or NAT can't start"]);

    $command = $step->plan($ctx)[0]->command;
    expect($command)
        ->toContain($ctx->helperPath.' Ux,')
        ->toContain('cat "$backup"') // the admin's own rules are kept
        ->and(strpos($command, 'apparmor_parser -Q'))->toBeInt()->toBeLessThan(strpos($command, 'apparmor_parser -r'));

    file_put_contents($ctx->system('/etc/apparmor.d/local/wg-quick'), "/usr/bin/foo ix,\n{$ctx->helperPath} Ux,\n", FILE_APPEND);
    expect($step->check($ctx))->toBe([]);
});

it('rolls the AppArmor rule back when the profile no longer compiles', function (bool $compiles) {
    $ctx = setupContext();
    mkdir($ctx->system('/etc/apparmor.d/local'), 0755, true);
    touch($ctx->system('/etc/apparmor.d/wg-quick'));
    file_put_contents($ctx->system('/etc/apparmor.d/local/wg-quick'), "/usr/bin/foo ix,\n");
    $command = (new AppArmor(new FakeShell))->plan($ctx)[0]->command;

    // A stub sudo runs commands as us; its apparmor_parser accepts or rejects the profile
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/sudo", "#!/bin/sh\n[ \"\$1\" = apparmor_parser ] && exit ".($compiles ? 0 : 1)."\n[ \"\$1\" = install ] && { shift; while [ \"\${1#-}\" != \"\$1\" ]; do [ \"\$1\" = -D ] && shift || shift 2; done; mkdir -p \"\$(dirname \"\$2\")\"; cp \"\$1\" \"\$2\"; exit; }\nexec \"\$@\"\n");
    chmod("{$this->tmp}/bin/sudo", 0755);
    exec('PATH='.escapeshellarg("{$this->tmp}/bin").':/usr/bin:/bin sh -c '.escapeshellarg($command).' 2>/dev/null', result_code: $rc);

    expect($rc === 0)->toBe($compiles)
        ->and(file_get_contents($ctx->system('/etc/apparmor.d/local/wg-quick')))->toBe($compiles
            ? "/usr/bin/foo ix,\n# Lets wg-quick run the WireGuard API root helper from PostUp/PostDown (php artisan wg:install)\n{$ctx->helperPath} Ux,\n"
            : "/usr/bin/foo ix,\n");
})->with(['compiles' => true, 'rejected' => false]);

// ─── Web user and server ────────────────────────────────────────────

it('refuses root as the web user', function () {
    $ctx = setupContext();
    $question = (new WebUser(new FakeShell))->questions($ctx)[0];

    expect($question->error('root', $ctx))->toContain('must not run as root')
        ->and($question->error('www-data', $ctx))->toBeNull()
        ->and($question->defaultFor($ctx))->toBe('www-data')
        ->and($question->defaultFor(setupContext('mac')))->toBe('deploy');
});

it('renders a systemd unit for each TLS mode', function (array $answers, string $site, string $tls, string $bind, string $flags) {
    $ctx = setupContext(answers: $answers);
    $unit = (new Server(new FakeShell))->unit($ctx);

    expect($unit)
        ->toContain("User=www-data\nGroup=www-data")
        ->toContain("Environment=\"WGLA_SITE_ADDRESS={$site}\"")
        ->toContain("Environment=\"WGLA_TLS_DIRECTIVE={$tls}\"")
        ->toContain("Environment=\"WGLA_BIND_DIRECTIVE={$bind}\"")
        ->toContain("octane:start --server=frankenphp {$flags} --caddyfile={$ctx->app()}/deploy/Caddyfile")
        ->toContain('AmbientCapabilities=CAP_NET_BIND_SERVICE')
        ->not->toContain('NoNewPrivileges=');
})->with([
    "Let's Encrypt" => [['tls' => 'letsencrypt', 'domain' => 'api.example.com', 'port' => '443'], 'https://api.example.com', '', '', '--host=0.0.0.0 --port=443 --admin-port=2019 --https'],
    "Let's Encrypt, other port" => [['tls' => 'letsencrypt', 'domain' => 'api.example.com', 'port' => '8443'], 'https://api.example.com:8443', '', '', '--host=0.0.0.0 --port=8443 --admin-port=2019 --https'],
    'own certificate' => [['tls' => 'cert', 'cert' => '/c.pem', 'key' => '/k.pem', 'port' => '443'], ':443', 'tls /c.pem /k.pem', '', '--host=0.0.0.0 --port=443 --admin-port=2019 --https'],
    // Listening on the bind address only, for whatever Host header the proxy passes on: an IP in
    // the site address would only match the Host header, and Caddy would listen everywhere
    'behind a proxy' => [['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080'], 'http://:8080', '', 'bind 127.0.0.1', '--host=127.0.0.1 --port=8080 --admin-port=2019'],
    'behind a proxy, on IPv6' => [['tls' => 'http', 'bind' => '::1', 'port' => '8080'], 'http://:8080', '', 'bind [::1]', '--host=::1 --port=8080 --admin-port=2019'],
]);

it('puts an IPv6 address the API listens on in brackets wherever it makes a URL of it', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '::1', 'port' => '8080']);
    $server = new Server(new FakeShell);
    // The health check asks the API there
    $shell = (new FakeShell)
        ->on('sudo -n -u :user sudo -n :helper version', fn () => helperVersion())
        ->on("curl -s -o /dev/null -w '%{http_code}' --max-time 3 :url", fn (array $b) => $b['url'] === 'http://[::1]:8080/health' ? '200' : '404');

    expect($server->localUrl($ctx))->toBe(['http://[::1]:8080', ''])
        ->and($server->publicUrl($ctx))->toBe('http://[::1]:8080 (behind your proxy)')
        ->and((new Health($shell, $server))->check($ctx))->toBe([])
        ->and($server->localUrl(setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080'])))->toBe(['http://127.0.0.1:8080', '']);
});

/** The curl that asks the API which code it runs (Server::staleness()). */
const STATUS_CURL = "curl -s --max-time 3 -w '\\n%{http_code}' -H @- :url";

/** An API that says it runs the code on disk, and an API key in .env to ask it with. */
function currentApi(FakeShell $shell, Context $ctx): FakeShell
{
    file_put_contents($ctx->app('.env'), "API_KEY=secret\n");

    return $shell->on(STATUS_CURL, fn () => json_encode(['app' => ['code' => App\Services\Server::codeFingerprint($ctx->app())]])."\n200");
}

it('restarts the API when deploy/Caddyfile changes, which a reload doesn\'t read', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    mkdir($ctx->app('deploy'));
    file_put_contents($ctx->app('deploy/Caddyfile'), "{\$WGLA_SITE_ADDRESS} {\n}\n");
    $shell = currentApi(new FakeShell, $ctx)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->otherwise(fn () => throw new CommandFailed);
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    expect($step->check($ctx))->toBe([])
        ->and($step->unit($ctx))->toContain("\n# Caddyfile sha256:".hash_file('sha256', $ctx->app('deploy/Caddyfile'))."\n");

    // An update brings a new one. The code fingerprint leaves it out, and the unit's ExecReload
    // (octane:reload) only restarts the workers.
    file_put_contents($ctx->app('deploy/Caddyfile'), "{\$WGLA_SITE_ADDRESS} {\n\tencode gzip\n}\n");

    expect($step->check($ctx))->toBe(['deploy/Caddyfile changed: the API only reads it when it starts'])
        ->and(array_map(fn ($action) => $action->command, $step->plan($ctx))[1])
        ->toBe('sudo systemctl daemon-reload && sudo systemctl enable wgla 2> /dev/null && sudo systemctl restart wgla');
});

it('explains the downsides of a non-standard HTTPS port', function () {
    $ctx = setupContext(answers: ['tls' => 'letsencrypt']);
    $port = collect((new Server(new FakeShell))->questions($ctx))->firstWhere('key', 'port');

    expect($port->warningFor('443', $ctx))->toBeNull()
        ->and($port->warningFor('8443', $ctx))->toContain('clients must add :8443')->toContain("Let's Encrypt still needs port 443 or 80")
        ->and($port->warningFor('8080', setupContext(answers: ['tls' => 'http'])))->toBeNull('Behind a proxy any port is fine');
});

it('wants the service installed, enabled and running', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed);
    $step = new Server($shell);

    expect($step->check($ctx))->toBe(['The wgla service is not installed, or its settings changed']);

    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));
    expect($step->check($ctx))->toBe(['The wgla service is not enabled and running']);

    $shell->on('systemctl is-enabled wgla', fn () => 'enabled')->on('systemctl is-active wgla', fn () => 'active');
    currentApi($shell, $ctx);
    expect($step->check($ctx))->toBe([]);

    $ctx->answers['port'] = '9090';
    expect($step->check($ctx))->toBe(['The wgla service is not installed, or its settings changed'], 'A changed answer re-renders the unit');
});

it('reloads a running API that still serves the code from before a deploy', function (string $running, array $problems, array $plan) {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    file_put_contents($ctx->app('.env'), "API_KEY=secret\n");
    $onDisk = App\Services\Server::codeFingerprint($ctx->app());
    $shell = (new FakeShell)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->on(':bin version', fn () => 'FrankenPHP v99.0.0 PHP 8.5.0 Caddy v2.10.0')
        ->on(STATUS_CURL, fn (array $b, ?string $input) => $b['url'] === 'http://127.0.0.1:8080/status' && $input === "api-key: secret\n"
            ? match ($running) {
                'older code' => json_encode(['app' => ['code' => 'older0000000000']])."\n200",
                'another key' => json_encode(['error' => 'Unauthorized'])."\n403",
                'no answer' => throw new CommandFailed('curl: (28) Operation timed out after 3001 milliseconds'),
                'an error' => "<html>Bad Gateway</html>\n502",
                'no code' => json_encode(['status' => 'ok'])."\n200",
                default => json_encode(['app' => ['code' => $onDisk]])."\n200",
            }
            : throw new CommandFailed);
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    expect($step->check($ctx))->toBe($problems)
        ->and(array_map(fn ($action) => $action->command, $step->plan($ctx)))->toBe($plan)
        ->and(implode(' ', array_column($shell->calls, 'bound')))->not->toContain('secret', 'The key never goes on a command line');
})->with([
    'after a deploy' => ['older code', ['The API still runs the code from before the last deploy'], ['sudo systemctl reload wgla']],
    'after a new API key' => ['another key', ["The API doesn't take the API key in .env: it still runs with its old settings"], ['sudo systemctl restart wgla']],
    'up to date' => ['current', [], []],
    // Can't tell is not current: whatever it runs, a restart runs what's on disk
    'not answering (hanging, or not up)' => ['no answer', ["The API doesn't answer at http://127.0.0.1:8080/status, so it can't be told which code it runs"], ['sudo systemctl restart wgla']],
    'failing' => ['an error', ["The API doesn't say which code it runs (http://127.0.0.1:8080/status answers 502)"], ['sudo systemctl restart wgla']],
    'not saying' => ['no code', ["The API doesn't say which code it runs (http://127.0.0.1:8080/status answers 200)"], ['sudo systemctl restart wgla']],
]);

it('can\'t ask the API which code it runs without an API key, and says how to set one', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    $shell = (new FakeShell)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->on(':bin version', fn () => 'FrankenPHP v99.0.0 PHP 8.5.0 Caddy v2.10.0');
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    // A restart wouldn't change that: the environment step sets the key
    expect($step->check($ctx))->toBe(['There is no API_KEY in .env to ask the API which code it runs'])
        ->and($step->plan($ctx))->toBe([])
        ->and($step->manual($ctx))->toBe('Set API_KEY in .env (php artisan wg:install --step=environment does).');
});

it('waits after its fix until the API serves the code on disk, for a while', function (string $before, int $answers, array $problems, int $waited) {
    Sleep::fake();
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    file_put_contents($ctx->app('.env'), "API_KEY=secret\n");
    // Until it has been asked $answers times, the API is what $before says: reloading (the old
    // code), restarting (not up), or still running with an old key (which no wait changes)
    $asked = 0;
    $shell = (new FakeShell)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->on(':bin version', fn () => 'FrankenPHP v99.0.0 PHP 8.5.0 Caddy v2.10.0')
        ->on(STATUS_CURL, function () use (&$asked, $answers, $before, $ctx) {
            return ++$asked > $answers ? json_encode(['app' => ['code' => App\Services\Server::codeFingerprint($ctx->app())]])."\n200" : match ($before) {
                'old code' => json_encode(['app' => ['code' => 'older0000000000']])."\n200",
                'not up' => throw new CommandFailed('curl: (7) Failed to connect'),
                'old key' => json_encode(['error' => 'Unauthorized'])."\n403",
            };
        });
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    expect($step->recheck($ctx))->toBe($problems);
    Sleep::assertSleptTimes($waited);
})->with([
    'reloaded at once' => ['old code', 0, [], 0],
    'reloaded after a few seconds' => ['old code', 3, [], 3],
    'restarted after a few seconds' => ['not up', 5, [], 5],
    // Bounded: an update that never gets its code served fails, and goes back
    'never reloaded' => ['old code', PHP_INT_MAX, ['The API still runs the code from before the last deploy'], Server::SETTLE_ATTEMPTS - 1],
    'never up' => ['not up', PHP_INT_MAX, ["The API doesn't answer at http://127.0.0.1:8080/status, so it can't be told which code it runs"], Server::SETTLE_ATTEMPTS - 1],
    'an old key: not waited for' => ['old key', PHP_INT_MAX, ["The API doesn't take the API key in .env: it still runs with its old settings"], 0],
]);

it('runs the app\'s own FrankenPHP, not another one on the PATH', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    // The one this step downloads, and one that FrankenPHP's own installer put in /usr/local/bin
    $other = "{$this->tmp}/usr/local/bin";
    mkdir($other, 0755, true);
    foreach ([$ctx->app('frankenphp'), "{$other}/frankenphp"] as $binary) {
        file_put_contents($binary, "#!/bin/sh\n");
        chmod($binary, 0755);
    }
    $unit = (new Server(new FakeShell))->unit($ctx);
    preg_match('/^Environment="PATH=([^"]+)"$/m', $unit, $path);
    expect($path)->not->toBe([], 'The unit sets the PATH');

    // Octane takes the first frankenphp on the PATH, then looks in the app
    expect((string) file_get_contents(__DIR__.'/../../../vendor/laravel/octane/src/FrankenPhp/Concerns/FindsFrankenPhpBinary.php'))
        ->toContain("(new ExecutableFinder())->find('frankenphp', null, [base_path()])");
    $find = function (string $path) use ($ctx) {
        $before = getenv('PATH');
        putenv("PATH={$path}");
        try {
            return (new ExecutableFinder)->find('frankenphp', null, [$ctx->app()]);
        } finally {
            putenv("PATH={$before}");
        }
    };

    expect($find(str_replace(':/usr/local/bin:', ":{$other}:", $path[1])))->toBe($ctx->app('frankenphp'))
        ->and($find(str_replace('/usr/local/bin', $other, Server::SERVICE_PATH)))->toBe("{$other}/frankenphp", 'Without the app first, the other one');
});

it('fingerprints the code by content, not by timestamps', function () {
    $ctx = setupContext();
    mkdir($ctx->app('app'), 0755, true);
    mkdir($ctx->app('storage'), 0755, true);
    file_put_contents($ctx->app('app/Thing.php'), '<?php // v1');
    file_put_contents($ctx->app('.env'), "APP_KEY=x\n");
    $fingerprint = fn () => App\Services\Server::codeFingerprint($ctx->app());
    $v1 = $fingerprint();

    file_put_contents($ctx->app('storage/log'), 'noise');
    touch($ctx->app('app/Thing.php'), time() - 86400);
    expect($fingerprint())->toBe($v1, 'storage/ and timestamps are not code');

    file_put_contents($ctx->app('app/Thing.php'), '<?php // v2');
    expect($fingerprint())->not->toBe($v1);

    file_put_contents($ctx->app('app/Thing.php'), '<?php // v1');
    expect($fingerprint())->toBe($v1, 'Back to the old code: the same code');

    file_put_contents($ctx->app('.env'), "APP_KEY=y\n");
    expect($fingerprint())->not->toBe($v1, '.env counts: workers read it at boot');
});

// ─── Installer ──────────────────────────────────────────────────────

it('saves answers in .env and reads them back on the next run', function () {
    $ctx = setupContext(answers: ['tls' => 'cert', 'port' => '8443', 'forward' => false, 'allow_default_route' => true, 'allow_own_networks' => false]);
    file_put_contents($ctx->app('.env'), "APP_KEY=x\n");
    $installer = new Installer((new FakeShell)->otherwise(fn () => 'deploy'), $ctx->helperPath);

    $installer->save($ctx);
    $again = $installer->context(['port' => '9443'], $ctx->app(), $ctx->root);
    $env = new EnvFile($ctx->app('.env'));

    expect($env->get('WGLA_SERVER_TLS'))->toBe('cert')
        ->and($env->get('WGLA_ALLOW_DEFAULT_ROUTE'))->toBe('true')
        ->and($env->get('WGLA_ALLOW_OWN_NETWORKS'))->toBe('false')
        ->and((new Policy(new FakeShell))->content($again))->toBe((new Policy(new FakeShell))->content($ctx), 'The same policy on the next run')
        ->and($again->answer('tls'))->toBe('cert')
        ->and($again->answer('forward'))->toBe('false')
        ->and($again->answer('port'))->toBe('9443', 'Options win over saved answers');
});

// ─── The API server: admin port, FrankenPHP ─────────────────────────

/** A server step that finds the given local ports taken. */
function serverStepWithPortsTaken(FakeShell $shell, array $taken): Server
{
    return new class($shell, $taken) extends Server
    {
        public function __construct(FakeShell $shell, private array $taken)
        {
            parent::__construct($shell);
        }

        protected function portFree(int $port): bool
        {
            return ! in_array($port, $this->taken, true);
        }
    };
}

it('gives FrankenPHP\'s admin API a port of its own', function (array $taken, array $answers, string $port) {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '2020', ...$answers]);
    $step = serverStepWithPortsTaken(new FakeShell, $taken);

    $step->after($ctx);

    expect($ctx->answer('admin_port'))->toBe($port)
        ->and($step->unit($ctx))->toContain("--port=2020 --admin-port={$port} ");
})->with([
    'the usual one when it is free' => [[], [], '2019'],
    // A Caddy reverse proxy on the same host has 2019; 2020 is the API itself here
    'the next free one otherwise' => [[2019], [], '2021'],
    'the one given by hand' => [[2019], ['admin_port' => '2500'], '2500'],
]);

it('keeps the admin port the installed service has', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), 'ExecStart=/usr/bin/php artisan octane:start --port=8080 --admin-port=2019 --caddyfile=x');

    // 2019 is "taken": by this very service. A re-run or an update must not move it.
    $step = serverStepWithPortsTaken(new FakeShell, [2019]);
    $step->after($ctx);

    expect($ctx->answer('admin_port'))->toBe('2019');
});

it('replaces a FrankenPHP that is older than Octane needs, and restarts the API with it', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    $shell = currentApi(new FakeShell, $ctx)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->on(':bin version', fn () => 'FrankenPHP v1.0.0 PHP 8.5.0 Caddy v2.8.0 h1:abc')
        ->on('getconf GNU_LIBC_VERSION', fn () => 'glibc 2.39');
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    expect($step->check($ctx))->toHaveCount(1)
        ->and($step->check($ctx)[0])->toStartWith('FrankenPHP 1.0.0 is older than this version of Octane needs (')
        ->and(array_map(fn ($action) => $action->command, $step->plan($ctx)))->toBe([$step->downloadFrankenPhp($ctx), 'sudo systemctl restart wgla']);
});

it('downloads FrankenPHP from its releases, not through the rate-limited GitHub API', function () {
    $ctx = setupContext(answers: ['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080']);
    $step = new Server((new FakeShell)->otherwise(fn () => throw new CommandFailed)); // no glibc found: the static build

    // api.github.com allows 60 requests an hour per IP address without a token, and CI runners
    // and offices share theirs: an install must not depend on it
    $download = $step->downloadFrankenPhp($ctx);
    expect($download)->toContain('https://github.com/php/frankenphp/releases/latest/download/frankenphp-linux-'.php_uname('m')."'")
        ->not->toContain('api.github.com')->not->toContain('octane:install')
        ->and(array_map(fn ($action) => $action->command, $step->plan($ctx))[0])->toBe($download, 'A first install downloads the same way');

    // Named as Octane's own installer names them, which is what the project publishes
    $octane = (string) file_get_contents(__DIR__.'/../../../vendor/laravel/octane/src/Commands/Concerns/InstallsFrankenPhpDependencies.php');
    expect($octane)->toContain('"frankenphp-linux-x86_64$gnu"', '"frankenphp-linux-aarch64$gnu"', '"frankenphp-mac-$arch"', "['getconf', 'GNU_LIBC_VERSION']")
        ->and((new Server((new FakeShell)->on('getconf GNU_LIBC_VERSION', fn () => 'glibc 2.39')))->downloadFrankenPhp($ctx))->toContain('/frankenphp-linux-'.php_uname('m')."-gnu'")
        ->and((new Server(new FakeShell))->downloadFrankenPhp(setupContext('mac')))->toContain('/frankenphp-mac-'.php_uname('m')."'");
});

it('knows the installed and the current FrankenPHP release without the API', function () {
    $ctx = setupContext();
    touch($ctx->app('frankenphp'));
    chmod($ctx->app('frankenphp'), 0755);
    $redirect = 'https://github.com/php/frankenphp/releases/tag/v1.14.0';
    $shell = (new FakeShell)
        ->on(':bin version', fn () => 'FrankenPHP v1.13.2 PHP 8.5.0 Caddy v2.10.0 h1:abc')
        ->on("curl -fsS -o /dev/null -w '%{redirect_url}' --max-time 10 :url", function (array $b) use (&$redirect) {
            expect($b['url'])->toBe('https://github.com/php/frankenphp/releases/latest');

            return $redirect ?? throw new CommandFailed('curl: (6) Could not resolve host');
        });
    $step = new Server($shell);

    expect($step->frankenPhpVersion($ctx))->toBe('1.13.2')
        ->and($step->latestFrankenPhp())->toBe('1.14.0');

    $redirect = null; // GitHub can't be reached: unknown, not "current"
    expect($step->latestFrankenPhp())->toBeNull()
        ->and($step->frankenPhpVersion(setupContext()))->toBeNull('No binary yet');
});

it('keeps the installed FrankenPHP unless a complete, working one was downloaded', function (string $curl, int $exit, string $installed) {
    $ctx = setupContext();
    file_put_contents($ctx->app('frankenphp'), 'old binary');
    chmod($ctx->app('frankenphp'), 0755);
    // A curl that "downloads" what the case says, where the real one would fetch the release
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/curl", "#!/bin/sh\n{$curl}\n");
    chmod("{$this->tmp}/bin/curl", 0755);

    $step = new Server((new FakeShell)->otherwise(fn () => throw new CommandFailed));
    $process = Process::fromShellCommandline($step->downloadFrankenPhp($ctx), env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin"]);
    $process->run();

    expect($process->getExitCode())->toBe($exit, $process->getErrorOutput())
        ->and(file_get_contents($ctx->app('frankenphp')))->toBe($installed)
        ->and(file_exists($ctx->app('frankenphp.new')))->toBeFalse('Nothing half-downloaded is left behind')
        ->and(file_exists($ctx->app('frankenphp.previous')))->toBe($exit === 0, 'Only what was replaced is kept');
})->with([
    'a working binary' => ["printf '#!/bin/sh\\necho FrankenPHP v9.9.9\\n' > frankenphp.new", 0, "#!/bin/sh\necho FrankenPHP v9.9.9\n"],
    'a failed download' => ['exit 22', 1, 'old binary'],
    'an error page instead of a binary' => ["printf '<html>rate limited</html>' > frankenphp.new", 1, 'old binary'],
]);

it('keeps the FrankenPHP a download replaces, for the way back from a failed update to put back', function () {
    $ctx = setupContext();
    file_put_contents($ctx->app('frankenphp'), 'old binary');
    chmod($ctx->app('frankenphp'), 0755);
    mkdir("{$this->tmp}/bin");
    file_put_contents("{$this->tmp}/bin/curl", "#!/bin/sh\nprintf '#!/bin/sh\\necho FrankenPHP v9.9.9\\n' > frankenphp.new\n");
    chmod("{$this->tmp}/bin/curl", 0755);
    $updater = new Updater((new FakeShell)->on('git -C :app rev-parse --git-path wgla-update', fn () => "{$this->tmp}/wgla-update"));
    $before = $updater->begin($ctx, 'aaa111', 'bbb222')['frankenphp'];

    expect($updater->restoreFrankenPhp($ctx, $before))->toBeFalse('Nothing replaced it yet');

    // Stage 2 of the update downloads the current release
    $process = Process::fromShellCommandline((new Server((new FakeShell)->otherwise(fn () => throw new CommandFailed)))->downloadFrankenPhp($ctx), env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin"]);
    $process->run();
    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and(file_get_contents($ctx->app('frankenphp.previous')))->toBe('old binary');

    expect($updater->restoreFrankenPhp($ctx, $before))->toBeTrue()
        ->and(file_get_contents($ctx->app('frankenphp')))->toBe('old binary')
        ->and($updater->restoreFrankenPhp($ctx, $before))->toBeFalse('Back already');

    // Replaced again, with the one from before gone: there's nothing to put back
    file_put_contents($ctx->app('frankenphp'), 'another binary');
    expect($updater->restoreFrankenPhp($ctx, $before))->toBeNull()
        ->and(file_get_contents($ctx->app('frankenphp')))->toBe('another binary')
        ->and($updater->restoreFrankenPhp($ctx, null))->toBeFalse('There was none before the update');
});

it('records an update in git\'s directory until it is over', function () {
    $ctx = setupContext();
    mkdir($ctx->app('.git'));
    // As git prints it: relative to the directory it ran in (-C, the app)
    $updater = new Updater((new FakeShell)->on('git -C :app rev-parse --git-path wgla-update', fn () => '.git/wgla-update'));

    expect($updater->recordPath($ctx))->toBe($ctx->app('.git/wgla-update'))
        ->and($updater->unfinished($ctx))->toBeNull();

    $update = $updater->begin($ctx, 'aaa111', 'bbb222');

    expect($update)->toBe(['from' => 'aaa111', 'to' => 'bbb222', 'frankenphp' => null], 'No FrankenPHP before it')
        ->and($updater->unfinished($ctx))->toBe($update, 'What the next run reads')
        ->and($updater->end($ctx))->toBeTrue()
        ->and($updater->unfinished($ctx))->toBeNull();
});

it('tells an update whether FrankenPHP changed', function (?string $downloaded, int $exit, ?bool $changed) {
    $ctx = setupContext();
    file_put_contents($ctx->app('frankenphp'), 'release 1');
    $shell = (new FakeShell)->onInteractive(function () use ($ctx, $downloaded, $exit) {
        if ($downloaded !== null) {
            file_put_contents($ctx->app('frankenphp'), $downloaded);
        }

        return $exit;
    });

    expect((new Updater($shell))->refreshFrankenPhp($ctx, 'fetch it'))->toBe($changed)
        ->and($shell->interactive)->toBe(['fetch it']);
})->with([
    'a new release' => ['release 2', 0, true],
    'the same release' => ['release 1', 0, false],
    'a failed download' => [null, 1, null],
]);

it('takes the newest release, not a pre-release, as the latest', function (string $tags, ?string $latest) {
    $ctx = setupContext();
    // As `git tag --sort=-v:refname` lists them: a pre-release above the release it leads up to
    $shell = (new FakeShell)->on("git -C :app tag --list 'v[0-9]*' --sort=-v:refname", fn () => $tags);

    expect((new Updater($shell))->latestRelease($ctx))->toBe($latest);
})->with([
    ["v1.1.0-rc1\nv1.1.0-beta\nv1.1.0\nv1.0.0", 'v1.1.0'],
    ["v2.0.0-rc1\nv1.4.2", 'v1.4.2'],
    ['v1.0.0-rc1', null],
    ['', null],
]);

// ─── Firewall rules kept in place ───────────────────────────────────

it('has the root helper put missing firewall rules back every minute', function () {
    $ctx = setupContext();
    $shell = (new FakeShell)->otherwise(fn () => throw new CommandFailed);
    $step = new FirewallRepair($shell);

    expect($step->applies($ctx))->toBeTrue()
        ->and($step->applies(setupContext('mac')))->toBeFalse('systemd only')
        ->and($step->service($ctx))->toContain("ExecStart={$ctx->helperPath} firewall-repair\n", "Type=oneshot\n", "LogLevelMax=notice\n")
        ->and($step->timer())->toContain("OnUnitActiveSec=1min\n", "WantedBy=timers.target\n")
        ->and($step->check($ctx))->toBe(['The timer that puts missing firewall rules back is not installed, or its settings changed']);

    $commands = array_map(fn ($action) => $action->command, $step->plan($ctx));
    expect($commands[0])->toContain("sudo install -o root -g root -m 644 \"\$tmp/service\" '{$ctx->system(FirewallRepair::SERVICE)}'", "'{$ctx->system(FirewallRepair::TIMER)}'")
        ->and($commands[1])->toBe('sudo systemctl daemon-reload && sudo systemctl enable wgla-firewall.timer 2> /dev/null && sudo systemctl restart wgla-firewall.timer');

    mkdir(dirname($ctx->system(FirewallRepair::SERVICE)), 0755, true);
    file_put_contents($ctx->system(FirewallRepair::SERVICE), $step->service($ctx));
    file_put_contents($ctx->system(FirewallRepair::TIMER), $step->timer());
    expect($step->check($ctx))->toBe(['The timer that puts missing firewall rules back is not enabled and running']);

    $shell->on('systemctl is-enabled wgla-firewall.timer', fn () => 'enabled')->on('systemctl is-active wgla-firewall.timer', fn () => 'active');
    expect($step->check($ctx))->toBe([]);
});

it('writes the timer units the printed command says it writes', function () {
    $ctx = setupContext();
    $step = new FirewallRepair(new FakeShell);
    // The same command, installing as this user into the temp root instead of as root into /etc
    $command = str_replace('sudo install -o root -g root -m 644', 'install -m 644', $step->plan($ctx)[0]->command);
    mkdir(dirname($ctx->system(FirewallRepair::SERVICE)), 0755, true);

    $process = Process::fromShellCommandline($command);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and(file_get_contents($ctx->system(FirewallRepair::SERVICE)))->toBe($step->service($ctx))
        ->and(file_get_contents($ctx->system(FirewallRepair::TIMER)))->toBe($step->timer());
});
