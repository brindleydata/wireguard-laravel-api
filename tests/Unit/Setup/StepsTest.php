<?php

use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Installer;
use App\Setup\Steps\Environment;
use App\Setup\Steps\Forwarding;
use App\Setup\Steps\Helper;
use App\Setup\Steps\Permissions;
use App\Setup\Steps\PfAnchors;
use App\Setup\Steps\Server;
use App\Setup\Steps\Sudoers;
use App\Setup\Steps\WebUser;
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
    $step = new Environment(new FakeShell);

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

// ─── Helper and sudoers ─────────────────────────────────────────────

it('wants the bundled helper installed, owned by root', function () {
    $ctx = setupContext();
    $step = new Helper((new FakeShell)->otherwise(fn () => throw new CommandFailed));

    expect($step->check($ctx))->toBe(["The root helper is not installed at {$ctx->helperPath}"])
        ->and($step->plan($ctx)[0]->command)->toBe(
            "sudo mkdir -p '".dirname($ctx->helperPath)."' && sudo install -o root -g root -m 755 '{$ctx->bundledHelper}' '{$ctx->helperPath}'"
        );

    mkdir(dirname($ctx->helperPath), 0755, true);
    file_put_contents($ctx->helperPath, str_replace('VERSION=1', 'VERSION=0', file_get_contents($ctx->bundledHelper)));

    expect($step->check($ctx))->toContain("{$ctx->helperPath} differs from the bundled helper (installed v0, app v1)")
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

it('turns IP forwarding on persistently on Linux, only when links route traffic', function () {
    $ctx = setupContext(answers: ['forward' => true]);
    $step = new Forwarding((new FakeShell)->on('sysctl -n net.ipv4.ip_forward', fn () => '0'));

    expect($step->check($ctx))->toBe(['IP forwarding is off', 'IP forwarding is not kept across reboots'])
        ->and($step->plan($ctx)[0]->command)->toContain("sudo tee '{$ctx->system('/etc/sysctl.d/99-wireguard.conf')}'");

    $ctx->answers['forward'] = false;
    expect($step->check($ctx))->toBe([]);
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
