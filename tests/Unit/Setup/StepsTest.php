<?php

use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Installer;
use App\Setup\Steps\AppArmor;
use App\Setup\Steps\Environment;
use App\Setup\Steps\FirewallRepair;
use App\Setup\Steps\Forwarding;
use App\Setup\Steps\Helper;
use App\Setup\Steps\Permissions;
use App\Setup\Steps\PfAnchors;
use App\Setup\Steps\Server;
use App\Setup\Steps\Shortcut;
use App\Setup\Steps\Sudoers;
use App\Setup\Steps\WebUser;
use App\Setup\Updater;
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
    file_put_contents("{$tmp}/app/.env.example", "APP_KEY=\nAPI_KEY=\nWIREGUARD_HOSTNAME=\n");

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

it('creates .env with fresh keys and makes it private', function (bool $separate) {
    $ctx = setupContext(answers: ['hostname' => 'vpn.example.com', 'web_user' => $separate ? 'www-data' : 'deploy']);
    $step = new Environment((new FakeShell)->otherwise(fn () => throw new CommandFailed('not a git checkout')));

    expect($step->check($ctx))->toBe(['There is no .env file']);

    $plan = $step->plan($ctx);
    ($plan[0]->callback)($ctx);
    $env = new EnvFile($ctx->app('.env'));

    expect($env->get('APP_KEY'))->toStartWith('base64:')
        ->and($env->get('API_KEY'))->toMatch('/^[0-9a-f]{64}$/')
        ->and($env->get('WIREGUARD_HOSTNAME'))->toBe('vpn.example.com')
        ->and($env->get('OCTANE_SERVER'))->toBe('frankenphp')
        ->and($plan[1]->command)->toBe($separate
            ? "sudo chgrp 'www-data' '{$ctx->app('.env')}' && chmod 640 '{$ctx->app('.env')}'"
            : "chmod 600 '{$ctx->app('.env')}'");

    // Keys are kept on a re-run
    $key = $env->get('API_KEY');
    ($step->plan($ctx)[0]->callback)($ctx);
    expect($env->get('API_KEY'))->toBe($key);
})->with(['separate web user' => true, 'same user (macOS dev)' => false]);

it('records the checked-out release as APP_VERSION', function () {
    $ctx = setupContext(answers: ['hostname' => 'vpn.example.com']);
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

it('keeps the code, bootstrap/cache included, read-only for the web user', function () {
    $ctx = setupContext();
    // The web user can write everything: a wrong ownership to fix
    $shell = (new FakeShell)->on('sudo -n -u :user test -w :path', fn () => '')->on('sudo -n -u :user test -r :path', fn () => '');
    $step = new Permissions($shell);

    expect($step->check($ctx))
        ->toContain('www-data can change the code in bootstrap/cache/')
        ->toContain('www-data can change the code in app/')
        ->toContain('www-data can change the code in the app directory');

    [$code, $storage] = $step->plan($ctx);
    expect($code->command)->toBe("sudo chown -R 'deploy:deploy' '{$ctx->app()}' && sudo chmod -R go-w '{$ctx->app()}'")
        ->and($storage->command)->toContain("sudo chown -R 'www-data:www-data' '{$ctx->app('storage')}' &&")
        ->and($storage->command)->not->toContain('bootstrap/cache');
});

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
    foreach (['sudo', 'php'] as $stub) {
        // Each prints its argv; php lists commands as `artisan list wg --raw` does
        $list = $stub === 'php' ? "[ \"\$2\" = list ] && { printf 'wg:links         List WireGuard links\\nwg:link:create   Create a WireGuard link\\n'; exit; }\n" : '';
        file_put_contents("{$this->tmp}/bin/{$stub}", "#!/bin/sh\n{$list}printf '%s' {$stub}; for a in \"\$@\"; do printf ' [%s]' \"\$a\"; done\n");
        chmod("{$this->tmp}/bin/{$stub}", 0755);
    }
    // php is the stub; the web user is whoever runs the test when the case asks for it
    $me = trim((string) shell_exec('id -un'));
    $ctx = new Context(os: 'linux', appPath: $ctx->appPath, deployUser: 'deploy', deployGroup: 'deploy', php: "{$this->tmp}/bin/php",
        helperPath: $ctx->helperPath, bundledHelper: $ctx->bundledHelper, root: $ctx->root,
        answers: ['web_user' => ($env['AS_WEB'] ?? false) ? $me : 'www-data', 'web_group' => 'www-data']);
    file_put_contents("{$this->tmp}/wgla", (new Shortcut(new FakeShell))->script($ctx));
    chmod("{$this->tmp}/wgla", 0755);

    $process = new Process(["{$this->tmp}/wgla", ...$args], env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin", ...array_diff_key($env, ['AS_WEB' => 1])]);
    $process->run();

    expect(trim($process->getOutput()))->toBe(strtr($expected, ['PHP' => "{$this->tmp}/bin/php", 'ARTISAN' => "{$ctx->app()}/artisan"]));
})->with([
    'no command: the commands, as wgla takes them' => [[], [], "Usage: wgla <command> [arguments] [options]\n\n  links         List WireGuard links\n  link:create   Create a WireGuard link\n\nwgla help <command> shows its arguments and options."],
    'a link command' => [['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]'],
    'arguments as given' => [['wg:peer:create', 'wg0', "--name=Ана's phone"], [], "sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:peer:create] [wg0] [--name=Ана's phone]"],
    'install and update' => [['update', '--to=v1.2.0'], [], 'sudo [-H] [-u] [deploy] [--] [PHP] [ARTISAN] [wg:update] [--to=v1.2.0]'],
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
    chmod("{$this->tmp}/bin/php", 0755);
    chmod("{$this->tmp}/bin/sudo", 0755);
    // Run through a relative symlink elsewhere, as when it's linked into the PATH
    $command = "{$app}/bin/wgla";
    if ($symlink) {
        mkdir("{$this->tmp}/links");
        symlink('../checkout/bin/wgla', $command = "{$this->tmp}/links/wgla");
    }

    $process = new Process([$command, ...$args], env: ['PATH' => "{$this->tmp}/bin:/usr/bin:/bin", ...$env]);
    $process->run();

    expect(trim($process->getOutput()))->toBe(strtr($expected, [
        'PHP' => "{$this->tmp}/bin/php", 'ARTISAN' => realpath($app).'/artisan', 'BESIDE' => realpath($app).'/bin/wgla-helper',
    ]), $process->getErrorOutput());
})->with([
    'the web user from .env' => ["WGLA_WEB_USER=\"www-data\"\nWIREGUARD_HELPER=INSTALLED\n", ['links'], [], 'sudo [-H] [-u] [www-data] [--] [PHP] [ARTISAN] [wg:links]', false],
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

it('renders a systemd unit for each TLS mode', function (array $answers, string $site, string $tls, string $flags) {
    $ctx = setupContext(answers: $answers);
    $unit = (new Server(new FakeShell))->unit($ctx);

    expect($unit)
        ->toContain("User=www-data\nGroup=www-data")
        ->toContain("Environment=\"WGLA_SITE_ADDRESS={$site}\"")
        ->toContain("Environment=\"WGLA_TLS_DIRECTIVE={$tls}\"")
        ->toContain("octane:start --server=frankenphp {$flags} --caddyfile={$ctx->app()}/deploy/Caddyfile")
        ->toContain('AmbientCapabilities=CAP_NET_BIND_SERVICE')
        ->not->toContain('NoNewPrivileges=');
})->with([
    "Let's Encrypt" => [['tls' => 'letsencrypt', 'domain' => 'api.example.com', 'port' => '443'], 'https://api.example.com', '', '--host=0.0.0.0 --port=443 --admin-port=2019 --https'],
    "Let's Encrypt, other port" => [['tls' => 'letsencrypt', 'domain' => 'api.example.com', 'port' => '8443'], 'https://api.example.com:8443', '', '--host=0.0.0.0 --port=8443 --admin-port=2019 --https'],
    'own certificate' => [['tls' => 'cert', 'cert' => '/c.pem', 'key' => '/k.pem', 'port' => '443'], ':443', 'tls /c.pem /k.pem', '--host=0.0.0.0 --port=443 --admin-port=2019 --https'],
    'behind a proxy' => [['tls' => 'http', 'bind' => '127.0.0.1', 'port' => '8080'], 'http://127.0.0.1:8080', '', '--host=127.0.0.1 --port=8080 --admin-port=2019'],
]);

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
        ->on("curl -s --max-time 3 -w '\\n%{http_code}' -H @- :url", fn (array $b, ?string $input) => $b['url'] === 'http://127.0.0.1:8080/status' && $input === "api-key: secret\n"
            ? match ($running) {
                'older code' => json_encode(['app' => ['code' => 'older0000000000']])."\n200",
                'another key' => json_encode(['error' => 'Unauthorized'])."\n403",
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
]);

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
    $ctx = setupContext(answers: ['tls' => 'cert', 'port' => '8443', 'forward' => false]);
    file_put_contents($ctx->app('.env'), "APP_KEY=x\n");
    $installer = new Installer((new FakeShell)->otherwise(fn () => 'deploy'), $ctx->helperPath);

    $installer->save($ctx);
    $again = $installer->context(['port' => '9443'], $ctx->app(), $ctx->root);

    expect((new EnvFile($ctx->app('.env')))->get('WGLA_SERVER_TLS'))->toBe('cert')
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
    $shell = (new FakeShell)
        ->on('systemctl is-enabled wgla', fn () => 'enabled')
        ->on('systemctl is-active wgla', fn () => 'active')
        ->on(':bin version', fn () => 'FrankenPHP v1.0.0 PHP 8.5.0 Caddy v2.8.0 h1:abc');
    $step = new Server($shell);
    mkdir(dirname($ctx->system(Server::UNIT)), 0755, true);
    file_put_contents($ctx->system(Server::UNIT), $step->unit($ctx));

    expect($step->check($ctx))->toHaveCount(1)
        ->and($step->check($ctx)[0])->toStartWith('FrankenPHP 1.0.0 is older than this version of Octane needs (')
        ->and(array_map(fn ($action) => $action->command, $step->plan($ctx)))->toBe([$step->replaceFrankenPhp($ctx), 'sudo systemctl restart wgla'])
        ->and($step->replaceFrankenPhp($ctx))->toContain('mv frankenphp frankenphp.old', 'octane:install --server=frankenphp --no-interaction', 'mv -f frankenphp.old frankenphp');
});

it('keeps the installed FrankenPHP when the new one cannot be fetched', function () {
    $ctx = setupContext();
    file_put_contents($ctx->app('frankenphp'), 'old binary');
    chmod($ctx->app('frankenphp'), 0755);
    file_put_contents($ctx->app('artisan'), "<?php exit(1); // the download fails\n");
    $step = new Server(new FakeShell);
    $command = str_replace("'/usr/bin/php'", escapeshellarg(PHP_BINARY), $step->replaceFrankenPhp($ctx));

    $process = Process::fromShellCommandline($command);
    $process->run();

    expect($process->getExitCode())->toBe(1)
        ->and(file_get_contents($ctx->app('frankenphp')))->toBe('old binary')
        ->and(file_exists($ctx->app('frankenphp.old')))->toBeFalse();

    // And takes the new one when the download works
    file_put_contents($ctx->app('artisan'), "<?php file_put_contents(__DIR__.'/frankenphp', 'new binary'); chmod(__DIR__.'/frankenphp', 0755);\n");
    $process = Process::fromShellCommandline($command);
    $process->run();

    expect($process->getExitCode())->toBe(0, $process->getErrorOutput())
        ->and(file_get_contents($ctx->app('frankenphp')))->toBe('new binary')
        ->and(file_exists($ctx->app('frankenphp.old')))->toBeFalse();
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
