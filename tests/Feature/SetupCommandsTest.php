<?php

use App\Services\Shell;
use App\Setup\Context;
use App\Setup\Installer;
use App\Setup\Question;
use App\Setup\Step;
use App\Setup\Steps\FirewallRepair;
use App\Setup\Steps\Health;
use App\Setup\Steps\Policy;
use App\Setup\Steps\Server;
use Illuminate\Support\Sleep;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;

/*
 * wg:install and wg:update as commands, with the host behind a FakeShell.
 */

beforeEach(function () {
    $this->shell = new FakeShell;
    $this->app->instance(Shell::class, $this->shell);

    // These commands run against this checkout: whatever they'd save must not land in its .env
    $this->installer = new class($this->shell) extends Installer
    {
        /** @var list<array<string, mixed>> */
        public array $saved = [];

        /** @var array<string, mixed> answers as an earlier install saved them in .env (this checkout has none) */
        public array $env = [];

        /** The app, when not this checkout */
        public ?string $appPath = null;

        /** @var list<Step>|null the steps, when not the real ones */
        public ?array $steps = null;

        public function save(Context $ctx): void
        {
            $this->saved[] = $ctx->answers;
        }

        public function context(array $given = [], ?string $appPath = null, string $root = ''): Context
        {
            return parent::context([...$this->env, ...array_filter($given, fn ($value) => $value !== null)], $appPath ?? $this->appPath, $root);
        }

        public function steps(): array
        {
            return $this->steps ?? parent::steps();
        }
    };
    $this->app->instance(Installer::class, $this->installer);

    // Where wg:update records an update in progress (git's directory, in this checkout's .git)
    $this->record = sys_get_temp_dir().'/wgla_update_record_'.bin2hex(random_bytes(4));
});

afterEach(function () {
    @unlink($this->record);
});

/**
 * A shell where the installer runs as $user and git answers from $git (command template => output).
 * An update is recorded in the test's own file.
 */
function setupShell(FakeShell $shell, string $user = 'deploy', array $git = []): FakeShell
{
    $git += ['rev-parse --git-path wgla-update' => test()->record];

    return $shell
        ->on('id -un', fn () => $user)
        ->on('id -gn', fn () => $user)
        ->otherwise(function (string $command, array $bindings) use ($git) {
            foreach ($git as $template => $output) {
                if ($command === "git -C :app {$template}") {
                    return $output instanceof Closure ? $output($bindings) : $output;
                }
            }
            throw new CommandFailed("not simulated: {$command}");
        });
}

/**
 * Interactive commands as wg:update runs them: a checkout moves HEAD ($head), as git's does even
 * when it exits 1 having only warned. $exit decides the exit codes (default: 0).
 */
function followCheckouts(FakeShell $shell, string &$head, ?Closure $exit = null): FakeShell
{
    return $shell->onInteractive(function (string $command) use (&$head, $exit) {
        if (preg_match("/ checkout --quiet (--force )?--detach '(\\w+)'$/", $command, $m)) {
            $head = $m[2];
        }

        return $exit === null ? 0 : $exit($command);
    });
}

// ─── wg:install ─────────────────────────────────────────────────────

it('prints the whole setup as a shell script without running anything', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--print' => true, '--user' => 'www-data', '--forward' => 'true',
        '--tls' => 'http', '--bind' => '127.0.0.1', '--port' => '8080'])
        ->expectsOutputToContain('set -e')
        ->expectsOutputToContain('sudo install -o root -g '.(PHP_OS_FAMILY === 'Darwin' ? 'wheel' : 'root')." -m 755 '".base_path('bin/wgla-helper')."'")
        ->expectsOutputToContain("printf '%s\\n' 'www-data ALL=(root) NOPASSWD: ")
        ->expectsOutputToContain("allow_default_route=false\nallow_own_networks=false\n' > \"\$tmp\"")
        // The script edits .env with this command, which saves every answer there (for wg:update)
        ->expectsOutputToContain("'".PHP_BINARY."' '".base_path('artisan')."' wg:install --step=environment --yes --user='www-data' --forward='true' --allow-default-route='false' --allow-own-networks='false' --tls='http' --port='8080' --bind='127.0.0.1'")
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe([], 'Nothing was run')
        ->and($this->installer->saved)->toBe([], 'And no answer was saved to .env');
});

it('refuses to run as root', function (array $options) {
    setupShell($this->shell, 'root');

    // A printed script would make root the owner of the code, too
    $this->artisan('wg:install', $options)
        ->expectsOutputToContain('not as root')
        ->assertFailed();
})->with(['installing' => [['--yes' => true]], 'printing' => [['--print' => true]]]);

it('needs passwordless sudo to fix things without asking', function () {
    setupShell($this->shell)->on('sudo -n true', fn () => throw new CommandFailed('sudo: a password is required'));

    $this->artisan('wg:install', ['--yes' => true])
        ->expectsOutputToContain('needs passwordless sudo')
        ->assertFailed();
});

it('asks for no password where sudo needs none, though `sudo -v` would', function () {
    // `sudo -v` wants a password unless every sudoers entry of the user has NOPASSWD (verifypw
    // defaults to `all`): not with `%wheel ALL=(ALL) ALL` beside `deploy ALL=(ALL) NOPASSWD: ALL`,
    // where every command runs without one
    $this->installer->steps = [];
    setupShell($this->shell)->on('sudo -n true', fn () => '');

    $this->artisan('wg:install')->assertSuccessful();

    expect($this->shell->interactive)->toBe([], 'sudo -v never ran');
});

it('asks for the sudo password once where sudo needs one', function () {
    $this->installer->steps = [];
    setupShell($this->shell)->on('sudo -n true', fn () => throw new CommandFailed('sudo: a password is required'));

    $this->artisan('wg:install')->assertSuccessful();
    expect($this->shell->interactive)->toBe(['sudo -v']);

    // A wrong password, or none given
    $this->shell->onInteractive(fn () => 1);
    $this->artisan('wg:install')->expectsOutputToContain('This needs sudo.')->assertFailed();
});

it('names a missing answer in non-interactive runs', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--print' => true, '--user' => 'www-data', '--forward' => 'true'])
        ->expectsOutputToContain('(pass --tls=…)')
        ->assertFailed();
})->skip(PHP_OS_FAMILY === 'Darwin', 'The server step (and its --tls question) only applies on Linux');

it('refuses to set up a server whose update never ended, and says to run wg:update', function () {
    // The code may be between two versions: wg:update goes back first
    file_put_contents($this->record, json_encode(['from' => 'old000', 'to' => 'new111', 'frankenphp' => null]));
    $this->installer->steps = []; // Were it to run anyway, nothing here may touch this checkout
    setupShell($this->shell, git: [
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
    ])->on('sudo -n true', fn () => '');

    $this->artisan('wg:install', ['--yes' => true])
        ->expectsOutputToContain("An update from v1.1.0 to v1.2.0 didn't end. Run php artisan wg:update first: it goes back to where that one started.")
        ->assertFailed();

    expect($this->shell->interactive)->toBe([])
        ->and($this->installer->saved)->toBe([], 'Nothing answered, nothing saved')
        ->and($this->shell->callsTo('sudo -n true'))->toBe([], 'Not even sudo asked for');

    // Printing changes nothing, so it still prints
    $this->installer->steps = null;
    $this->artisan('wg:install', ['--print' => true, '--user' => 'www-data', '--forward' => 'true',
        '--tls' => 'http', '--bind' => '127.0.0.1', '--port' => '8080'])
        ->expectsOutputToContain('set -e')
        ->assertSuccessful();
});

it('rejects unknown steps', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--step' => ['bogus']])
        ->expectsOutputToContain('Unknown step: bogus')
        ->assertFailed();
});

// ─── Wrong-user guard ───────────────────────────────────────────────

it('runs link and peer commands only as the web user', function () {
    config(['wireguard.web_user' => 'someone-else']);

    $this->artisan('wg:links')
        ->expectsOutputToContain('Run this as someone-else, the user the API runs as')
        ->expectsOutputToContain('wgla links ...')
        ->expectsOutputToContain('sudo -u someone-else php artisan wg:links')
        ->assertFailed();
});

it('lets the deploy user run help, install and update', function () {
    config(['wireguard.web_user' => 'someone-else']);
    setupShell($this->shell);

    $this->artisan('wg:help')->assertSuccessful();
    $this->artisan('wg:install', ['--step' => ['bogus']])->expectsOutputToContain('Unknown step')->assertFailed();
    $this->artisan('wg:update', ['--yes' => true])->doesntExpectOutputToContain('Run this as')->assertFailed();
});

it('does not guard before a web user is configured', function () {
    config(['wireguard.web_user' => null]);
    setupShell($this->shell);

    $this->artisan('wg:help')->assertSuccessful();
    $this->artisan('wg:links')->doesntExpectOutputToContain('Run this as');
});

// ─── wg:update ──────────────────────────────────────────────────────

it('only updates a git checkout', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    setupShell($this->shell, git: ['rev-parse --is-inside-work-tree' => 'false']);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('is not a git checkout')
        ->assertFailed();
});

it('refuses to overwrite local changes', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => ' M routes/api.php',
    ]);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('local changes')
        ->expectsOutputToContain('M routes/api.php')
        ->assertFailed();

    expect($this->shell->interactive)->toBe([]);
});

it('needs a release tag (or --branch) to update to', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => '',
    ]);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('There are no releases (tags vX.Y.Z) yet')
        ->assertFailed();
});

it('does nothing when already at the latest release', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => "v1.1.0\nv1.0.0",
        'rev-parse --verify --quiet :ref' => 'abc123',
        'describe --tags --exact-match :commit' => 'v1.1.0',
    ]);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('Already at v1.1.0')
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe([], 'No checkout, no composer');
});

it('shows the changelog and helper diff, then checks out, installs and finishes in a new process', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    $head = 'old000';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => "v1.1.0\nv1.0.0",
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'new111';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.0.0' : 'v1.1.0',
        'log --oneline --no-decorate :range' => 'new111 Helper version 2',
        'diff :from :to -- bin/wgla-helper' => "-VERSION=1\n+VERSION=2",
        'diff --name-only --no-renames -z :from :to' => "app/Services/WireGuard.php\0bin/wgla-helper",
    ])->on('sudo -n true', fn () => '');
    // What is recorded when the checkout moves: the update isn't over yet
    $recorded = [];
    followCheckouts($this->shell, $head, function () use (&$recorded) {
        $recorded[] = is_file($this->record) ? json_decode(file_get_contents($this->record), true) : null;

        return 0;
    });

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('Update v1.0.0 → v1.1.0')
        ->expectsOutputToContain('new111 Helper version 2')
        ->expectsOutputToContain('The root helper changes (it runs as root, review it)')
        ->expectsOutputToContain('Updated to v1.1.0')
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe([
        "git -C '".base_path()."' checkout --quiet --detach 'new111'",
        "composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='".base_path()."'",
        "'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='old000' --yes",
    ])
        ->and($recorded[0])->toMatchArray(['from' => 'old000', 'to' => 'new111'])
        ->and($this->record)->not->toBeFile('Over: the record is gone');
});

it('goes back to the previous version when finishing fails', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    $head = 'old000';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'bad222';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        'log --oneline --no-decorate :range' => 'bad222 Broken',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '');
    followCheckouts($this->shell, $head, fn (string $command) => str_contains($command, "--finish='old000'") ? 1 : 0);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('The update failed. Going back to v1.1.0')
        ->expectsOutputToContain('Back at v1.1.0')
        ->assertFailed();

    // Forced: whatever the failed update left half done goes
    expect($this->shell->interactive)->toContain("git -C '".base_path()."' checkout --quiet --force --detach 'old000'")
        ->toContain("'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='bad222' --back --yes")
        ->and($this->record)->not->toBeFile('Gone back: the update is over');
});

it('keeps the record of an update when going back fails too, and the next update starts there', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    $head = 'old000';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'bad222';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        'log --oneline --no-decorate :range' => 'bad222 Broken',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '');
    followCheckouts($this->shell, $head, fn (string $command) => str_contains($command, '--finish=') ? 1 : 0);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('Going back failed too. Check the output above, then run php artisan wg:update again: it goes back to v1.1.0 first.')
        ->assertFailed();

    expect(json_decode(file_get_contents($this->record), true))->toMatchArray(['from' => 'old000', 'to' => 'bad222']);

    // The next run goes back first, and fails the same way: the record stays for the one after
    $this->shell->interactive = [];
    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain("An update from v1.1.0 to v1.2.0 didn't end. Going back to v1.1.0 first.")
        ->expectsOutputToContain('Going back failed.')
        ->assertFailed();

    expect($this->shell->interactive)->toBe([
        "git -C '".base_path()."' checkout --quiet --force --detach 'old000'",
        "composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='".base_path()."'",
        "'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='bad222' --back --yes",
    ])->and($this->record)->toBeFile();
});

it('goes back from an update that never ended before it updates anew, instead of taking it for done', function (array $options, string $again) {
    // Interrupted after the checkout (Ctrl-C, a dropped SSH session): HEAD is at the release
    // already, without its stage 2. Taken for done, this would be "Already at v1.2.0".
    $this->installer->env = ['web_user' => 'www-data'];
    file_put_contents($this->record, json_encode(['from' => 'old000', 'to' => 'new111', 'frankenphp' => null]));
    $head = 'new111';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        // Half done: composer was interrupted
        'status --porcelain --untracked-files=no' => function () use (&$head) {
            return $head === 'new111' ? ' M composer.lock' : '';
        },
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'new111';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
    ])->on('sudo -n true', fn () => '');
    followCheckouts($this->shell, $head);

    $this->artisan('wg:update', $options)
        ->expectsOutputToContain("An update from v1.1.0 to v1.2.0 didn't end. Going back to v1.1.0 first.")
        ->expectsOutputToContain('Back at v1.1.0.')
        ->doesntExpectOutputToContain('Already at')
        ->assertSuccessful();

    // The update itself runs in a new process: the code now on disk is v1.1.0's
    expect($this->shell->interactive)->toBe([
        "git -C '".base_path()."' checkout --quiet --force --detach 'old000'",
        "composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='".base_path()."'",
        "'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='new111' --back --yes",
        "'".PHP_BINARY."' '".base_path('artisan')."' wg:update{$again}",
    ])->and($this->record)->not->toBeFile();
})->with([
    'to the latest release' => [['--yes' => true], ' --yes'],
    'to a release of its own' => [['--to' => 'v1.2.0', '--yes' => true], " --to='v1.2.0' --yes"],
]);

it('refuses a record of an unfinished update it can\'t read', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    file_put_contents($this->record, '{"from":');
    setupShell($this->shell, git: ['rev-parse --is-inside-work-tree' => 'true'])->on('sudo -n true', fn () => '');

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain("{$this->record} says an update didn't end, but not which one")
        ->assertFailed();

    expect($this->shell->interactive)->toBe([]);
});

it('does not go back from a checkout ahead of the latest release unless asked to', function () {
    // A clone of the main branch, three commits past v1.2.0
    $this->installer->env = ['web_user' => 'www-data'];
    $head = 'head333';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => "v1.2.0\nv1.1.0",
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'rel222';
        },
        'rev-list --left-right --count :range' => fn (array $b) => $b['range'] === 'rel222...head333' ? "0\t3" : throw new CommandFailed,
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'rel222' ? 'v1.2.0' : throw new CommandFailed,
        'rev-parse --short :commit' => fn (array $b) => $b['commit'],
        'log --oneline --no-decorate :range' => '',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '');
    followCheckouts($this->shell, $head);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('This checkout is 3 commits ahead of the latest release, v1.2.0: there is nothing to update.')
        ->expectsOutputToContain('--to=v1.2.0 goes back to that release, --branch= follows a branch.')
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe([], 'Nothing changed');

    // Asked for, it does
    $this->artisan('wg:update', ['--to' => 'v1.2.0', '--yes' => true])
        ->expectsOutputToContain('Update head333 → v1.2.0')
        ->expectsOutputToContain('(going back: no new commits)')
        ->expectsOutputToContain('Updated to v1.2.0')
        ->assertSuccessful();
});

it('puts the FrankenPHP from before back when an update that replaced it fails', function () {
    $app = sys_get_temp_dir().'/wgla_update_'.bin2hex(random_bytes(4));
    mkdir($app);
    file_put_contents("{$app}/frankenphp", 'release 1');
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->appPath = $app;
    $head = 'old000';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'new111';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        'log --oneline --no-decorate :range' => 'new111 New',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '');
    // The new version's stage 2 fetches a FrankenPHP (keeping the one it replaces, as the
    // download does) and restarts the API with it, which then fails its health check
    followCheckouts($this->shell, $head, function (string $command) use ($app) {
        if (str_contains($command, "--finish='old000'")) {
            rename("{$app}/frankenphp", "{$app}/frankenphp.previous");
            file_put_contents("{$app}/frankenphp", 'release 2, broken');

            return 1;
        }

        return 0;
    });

    try {
        $this->artisan('wg:update', ['--yes' => true])
            ->expectsOutputToContain('FrankenPHP is the one from before the update again')
            ->expectsOutputToContain('Back at v1.1.0')
            ->assertFailed();

        // Then the previous version's stage 2 restarts the API with it, and fetches none
        expect(file_get_contents("{$app}/frankenphp"))->toBe('release 1')
            ->and($this->shell->interactive)->toContain("'".PHP_BINARY."' '{$app}/artisan' wg:update --finish='new111' --back --yes");
    } finally {
        exec('rm -rf '.escapeshellarg($app));
    }
});

it('goes back when git leaves the checkout half done, even with exit status 0', function () {
    $this->installer->env = ['web_user' => 'www-data'];
    $head = 'old000';
    $status = '';
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => function () use (&$status) {
            return $status;
        },
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => function (array $b) use (&$head) {
            return $b['ref'] === 'HEAD^{commit}' ? $head : 'new111';
        },
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        'log --oneline --no-decorate :range' => 'new111 New',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '');
    // A file git has no right to replace: it only warns, and exits 0. Going back it warns again
    // and exits 1, with every file as it was (git 2.x does just that)
    followCheckouts($this->shell, $head, function (string $command) use (&$status) {
        if (! str_contains($command, ' checkout ')) {
            return 0;
        }
        $status = str_ends_with($command, "'new111'") ? ' M storage/framework/.gitignore' : '';

        return str_contains($command, '--force') ? 1 : 0;
    });

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('The checkout is incomplete')
        ->expectsOutputToContain('M storage/framework/.gitignore')
        ->expectsOutputToContain('Back at v1.1.0')
        ->assertFailed();

    // Not the new version's dependencies or stage 2: straight back
    expect($this->shell->interactive)->toBe([
        "git -C '".base_path()."' checkout --quiet --detach 'new111'",
        "git -C '".base_path()."' checkout --quiet --force --detach 'old000'",
        "composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='".base_path()."'",
        "'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='new111' --back --yes",
    ]);
});

it('refuses, before changing anything, an update that changes files the deploy user can\'t write', function () {
    // storage/ as wg:install leaves it: the web user's
    $app = sys_get_temp_dir().'/wgla_update_'.bin2hex(random_bytes(4));
    mkdir("{$app}/app", 0755, true);
    mkdir("{$app}/storage/framework", 0755, true);
    chmod("{$app}/storage/framework", 0555);
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->appPath = $app;
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => fn (array $b) => $b['ref'] === 'HEAD^{commit}' ? 'old000' : 'new111',
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        // A changed file, and one in a directory that doesn't exist yet
        'diff --name-only --no-renames -z :from :to' => "app/Setup/Updater.php\0storage/framework/.gitignore\0storage/framework/locks/.gitignore",
    ])->on('sudo -n true', fn () => '');

    try {
        $this->artisan('wg:update', ['--yes' => true])
            ->expectsOutputToContain("This update changes files where deploy can't write")
            ->expectsOutputToContain('  storage/framework/.gitignore')
            ->expectsOutputToContain('  storage/framework/locks/.gitignore')
            ->doesntExpectOutputToContain('  app/Setup/Updater.php')
            ->expectsOutputToContain("sudo chown deploy '{$app}/storage/framework'")
            ->assertFailed();

        expect($this->shell->interactive)->toBe([], 'Nothing checked out');
    } finally {
        chmod("{$app}/storage/framework", 0755);
        exec('rm -rf '.escapeshellarg($app));
    }
})->skip(fn () => function_exists('posix_geteuid') && posix_geteuid() === 0, 'root can write anywhere');

/** Stand-ins for the server and health steps of stage 2: FrankenPHP $installed is there, $latest is the current release. */
function stage2Steps(FakeShell $shell, string $installed, string $latest): array
{
    $server = new class($shell, $installed, $latest) extends Server
    {
        public function __construct(FakeShell $shell, private string $installed, private string $latest)
        {
            parent::__construct($shell);
        }

        public function applies(Context $ctx): bool
        {
            return true;
        }

        public function questions(Context $ctx): array
        {
            return [];
        }

        public function after(Context $ctx): void {}

        public function check(Context $ctx): array
        {
            return [];
        }

        public function frankenPhpVersion(Context $ctx): ?string
        {
            return $this->installed;
        }

        public function latestFrankenPhp(): ?string
        {
            return $this->latest;
        }

        public function downloadFrankenPhp(Context $ctx): string
        {
            return 'download frankenphp';
        }
    };

    return [$server, new class($shell, $server) extends Health
    {
        public function check(Context $ctx): array
        {
            return [];
        }
    }];
}

it('fetches the current FrankenPHP in stage 2, but not on the way back, which restarts the API all the same', function (array $options, array $commands, string $restart) {
    $app = sys_get_temp_dir().'/wgla_update_'.bin2hex(random_bytes(4));
    mkdir($app);
    file_put_contents("{$app}/frankenphp", 'release 1');
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->appPath = $app;
    $this->installer->steps = stage2Steps($this->shell, '1.0.0', '1.1.0');
    setupShell($this->shell)->on('sudo -n true', fn () => '')
        ->onInteractive(function (string $command) use ($app) {
            if ($command === 'download frankenphp') {
                file_put_contents("{$app}/frankenphp", 'release 2');
            }

            return 0;
        });

    try {
        // The way back runs with the FrankenPHP from before, which the API may not run (a reload
        // would keep the process the failed update started)
        $this->artisan('wg:update', ['--finish' => 'old000', '--yes' => true, ...$options])
            ->expectsOutputToContain($restart)
            ->assertSuccessful();

        expect($this->shell->interactive)->toBe($commands);
    } finally {
        exec('rm -rf '.escapeshellarg($app));
    }
})->with([
    'an update' => [[], ['download frankenphp', 'sudo systemctl restart wgla'], 'Restarting the API with the new FrankenPHP'],
    'the way back' => [['--back' => true], ['sudo systemctl restart wgla'], 'Restarting the API with the FrankenPHP from before'],
]);

it('fails stage 2 when the API never serves the new code, so the update goes back', function () {
    // Taken for done, the update would leave the API on the old code. Until now an API that
    // couldn't be asked counted as current, and a reload as done when systemctl returned.
    Sleep::fake();
    $app = sys_get_temp_dir().'/wgla_update_'.bin2hex(random_bytes(4));
    mkdir($app);
    file_put_contents("{$app}/.env", "API_KEY=secret\n");
    file_put_contents("{$app}/frankenphp", '');
    chmod("{$app}/frankenphp", 0755);
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->appPath = $app;
    // The service as installed and running; its FrankenPHP is the current release
    $this->installer->steps = [new class($this->shell) extends Server
    {
        public function applies(Context $ctx): bool
        {
            return true;
        }

        public function questions(Context $ctx): array
        {
            return [];
        }

        public function after(Context $ctx): void {}

        public function frankenPhpVersion(Context $ctx): ?string
        {
            return '9.9.9';
        }

        public function latestFrankenPhp(): ?string
        {
            return '9.9.9';
        }

        protected function unitCurrent(Context $ctx): bool
        {
            return true;
        }

        protected function running(): bool
        {
            return true;
        }
    }];
    setupShell($this->shell)->on('sudo -n true', fn () => '')
        ->on("curl -s --max-time 3 -w '\\n%{http_code}' -H @- :url", fn () => json_encode(['app' => ['code' => 'older0000000000']])."\n200");

    try {
        $this->artisan('wg:update', ['--finish' => 'old000', '--yes' => true])
            ->expectsOutputToContain('Reload the API with the code on disk')
            ->expectsOutputToContain('Still: The API still runs the code from before the last deploy')
            ->assertFailed();

        // Asked again for a while, not for ever
        expect($this->shell->interactive)->toBe(['sudo systemctl reload wgla']);
        Sleep::assertSleptTimes(Server::SETTLE_ATTEMPTS - 1);
    } finally {
        exec('rm -rf '.escapeshellarg($app));
    }
});

it('brings the route policy with an update', function () {
    // A step missing from WgUpdate::STEPS would only come with the next wg:install
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->steps = [new class($this->shell) extends Policy
    {
        public function check(Context $ctx): array
        {
            return [];
        }
    }];
    setupShell($this->shell)->on('sudo -n true', fn () => '');

    $this->artisan('wg:update', ['--finish' => 'old000', '--yes' => true])
        ->expectsOutputToContain('✓ Route policy')
        ->assertSuccessful();
});

it('puts the firewall rules of running links as the new helper writes them, right after its update', function () {
    // The old helper's rules read as missing to the new one where it writes others (replies only,
    // say): the timer would replace them within a minute, the update does at once
    $this->installer->env = ['web_user' => 'www-data'];
    $this->installer->steps = [new class($this->shell) extends FirewallRepair
    {
        public function applies(Context $ctx): bool
        {
            return true;
        }

        public function check(Context $ctx): array
        {
            return [];
        }
    }];
    setupShell($this->shell)->on('sudo -n true', fn () => '');

    $this->artisan('wg:update', ['--finish' => 'old000', '--yes' => true])
        ->expectsOutputToContain('Firewall rules of running links as this version writes them')
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe(['sudo systemctl start wgla-firewall.service']);
});

it('refuses to update a server whose setup is not saved in .env', function () {
    // Not even who runs the API: the steps would set the server up for the deploy user
    setupShell($this->shell);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('WGLA_WEB_USER is not in .env')
        ->assertFailed();

    expect($this->shell->interactive)->toBe([]);
});

// ─── Answers ────────────────────────────────────────────────────────

it('refuses a mistyped installer option', function (array $options, string $error) {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--print' => true, ...$options])->expectsOutputToContain($error)->assertFailed();
})->with([
    [['--forward' => 'maybe'], '--forward must be true or false'],
    [['--allow-default-route' => 'yes please'], '--allow-default-route must be true or false'],
    [['--allow-own-networks' => 'ture'], '--allow-own-networks must be true or false'],
    [['--admin-port' => '2019a'], '--admin-port must be a whole number'],
    [['--admin-port' => '70000'], '--admin-port must be a port number'],
]);

it('takes only one of a select\'s options, and names them', function (string $command, array $options, string $error) {
    // Nothing else would check it without a terminal: a mistyped --tls was plain HTTP on loopback.
    // An update has the answer from .env.
    $this->installer->env = ['web_user' => 'www-data', ...($command === 'wg:update' ? ['tls' => 'letsencrpyt'] : [])];
    $this->installer->steps = [new class($this->shell) extends Server
    {
        public function applies(Context $ctx): bool
        {
            return true; // Linux only otherwise
        }
    }];
    setupShell($this->shell)->on('sudo -n true', fn () => '');

    $this->artisan($command, $options)->expectsOutputToContain($error)->assertFailed();

    expect($this->shell->interactive)->toBe([]);
})->with([
    'wg:install' => ['wg:install', ['--print' => true, '--tls' => 'letsencrpyt'], "'letsencrpyt' is not one of: letsencrypt, cert, http. (pass --tls=…)"],
    // Which wg:install changes: an update has no options for it
    'wg:update' => ['wg:update', ['--finish' => 'old000', '--yes' => true], "'letsencrpyt' is not one of: letsencrypt, cert, http. (php artisan wg:install --tls=… sets it)"],
]);

it('names the option a missing answer comes from', function (string $answer, string $option) {
    setupShell($this->shell);
    $this->installer->steps = [new class($this->shell, $answer) extends Step
    {
        public function __construct(FakeShell $shell, private string $answer)
        {
            parent::__construct($shell);
        }

        public function key(): string
        {
            return 'stub';
        }

        public function title(): string
        {
            return 'Stub';
        }

        public function questions(Context $ctx): array
        {
            return [new Question($this->answer, 'Something')];
        }

        public function check(Context $ctx): array
        {
            return [];
        }

        public function plan(Context $ctx): array
        {
            return [];
        }
    }];

    $this->artisan('wg:install', ['--print' => true])
        ->expectsOutputToContain("Something: no answer (pass {$option}=…)")
        ->assertFailed();
})->with([
    ['web_user', '--user'],
    ['admin_port', '--admin-port'],
    ['allow_default_route', '--allow-default-route'],
]);

it('knows the web user\'s group in every command, not only after the web-user step', function () {
    // wg:update and `wg:install --step=server` never run that step, and the service unit and
    // .env need the group: "nobody" is in "nogroup", not in a group of its own name
    setupShell($this->shell)->on('id -gn :user', fn (array $b) => $b['user'] === 'nobody' ? 'nogroup' : $b['user']);

    $app = sys_get_temp_dir().'/wgla_no_app'; // no .env there: nothing saved from an earlier install

    expect($this->installer->context(['web_user' => 'nobody'], $app)->webGroup())->toBe('nogroup')
        ->and($this->installer->context([], $app)->webGroup())->toBe('deploy', 'No web user chosen yet: the deploy user itself');
});
