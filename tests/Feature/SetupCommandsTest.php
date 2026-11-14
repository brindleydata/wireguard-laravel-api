<?php

use App\Services\Shell;
use Tests\Fakes\CommandFailed;
use Tests\Fakes\FakeShell;

/*
 * wg:install and wg:update as commands, with the host behind a FakeShell.
 */

beforeEach(function () {
    $this->shell = new FakeShell;
    $this->app->instance(Shell::class, $this->shell);
});

/** A shell where the installer runs as $user and git answers from $git (command template => output). */
function setupShell(FakeShell $shell, string $user = 'deploy', array $git = []): FakeShell
{
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

// ─── wg:install ─────────────────────────────────────────────────────

it('prints the whole setup as a shell script without running anything', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--print' => true, '--user' => 'www-data', '--hostname' => 'vpn.example.com', '--forward' => 'true',
        '--tls' => 'http', '--bind' => '127.0.0.1', '--port' => '8080'])
        ->expectsOutputToContain('set -e')
        ->expectsOutputToContain('sudo install -o root -g '.(PHP_OS_FAMILY === 'Darwin' ? 'wheel' : 'root')." -m 755 '".base_path('bin/wgla-helper')."'")
        ->expectsOutputToContain("printf '%s\\n' 'www-data ALL=(root) NOPASSWD: ")
        ->assertSuccessful();

    expect($this->shell->interactive)->toBe([], 'Nothing was run');
});

it('refuses to run as root', function () {
    setupShell($this->shell, 'root');

    $this->artisan('wg:install', ['--yes' => true])
        ->expectsOutputToContain('not as root')
        ->assertFailed();
});

it('needs passwordless sudo to fix things without asking', function () {
    setupShell($this->shell)->on('sudo -n true', fn () => throw new CommandFailed('sudo: a password is required'));

    $this->artisan('wg:install', ['--yes' => true])
        ->expectsOutputToContain('needs passwordless sudo')
        ->assertFailed();
});

it('names a missing answer in non-interactive runs', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--print' => true, '--user' => 'www-data', '--hostname' => 'vpn.example.com', '--forward' => 'true'])
        ->expectsOutputToContain('(pass --tls=…)')
        ->assertFailed();
})->skip(PHP_OS_FAMILY === 'Darwin', 'The server step (and its --tls question) only applies on Linux');

it('rejects unknown steps', function () {
    setupShell($this->shell);

    $this->artisan('wg:install', ['--step' => ['bogus']])
        ->expectsOutputToContain('Unknown step: bogus')
        ->assertFailed();
});

// ─── wg:update ──────────────────────────────────────────────────────

it('only updates a git checkout', function () {
    setupShell($this->shell, git: ['rev-parse --is-inside-work-tree' => 'false']);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('is not a git checkout')
        ->assertFailed();
});

it('refuses to overwrite local changes', function () {
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
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => "v1.1.0\nv1.0.0",
        'rev-parse --verify --quiet :ref' => fn (array $b) => $b['ref'] === 'HEAD^{commit}' ? 'old000' : 'new111',
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.0.0' : 'v1.1.0',
        'log --oneline --no-decorate :range' => 'new111 Helper version 2',
        'diff :from :to -- bin/wgla-helper' => "-VERSION=1\n+VERSION=2",
    ])->on('sudo -n true', fn () => '');

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
    ]);
});

it('goes back to the previous version when finishing fails', function () {
    setupShell($this->shell, git: [
        'rev-parse --is-inside-work-tree' => 'true',
        'status --porcelain --untracked-files=no' => '',
        'fetch --quiet --tags --prune --force origin' => '',
        "tag --list 'v[0-9]*' --sort=-v:refname" => 'v1.2.0',
        'rev-parse --verify --quiet :ref' => fn (array $b) => $b['ref'] === 'HEAD^{commit}' ? 'old000' : 'bad222',
        'describe --tags --exact-match :commit' => fn (array $b) => $b['commit'] === 'old000' ? 'v1.1.0' : 'v1.2.0',
        'log --oneline --no-decorate :range' => 'bad222 Broken',
        'diff :from :to -- bin/wgla-helper' => '',
    ])->on('sudo -n true', fn () => '')
        ->onInteractive(fn (string $command) => str_contains($command, "--finish='old000'") ? 1 : 0);

    $this->artisan('wg:update', ['--yes' => true])
        ->expectsOutputToContain('The update failed. Going back to v1.1.0')
        ->expectsOutputToContain('Back at v1.1.0')
        ->assertFailed();

    expect($this->shell->interactive)->toContain("git -C '".base_path()."' checkout --quiet --detach 'old000'")
        ->toContain("'".PHP_BINARY."' '".base_path('artisan')."' wg:update --finish='bad222' --yes");
});
