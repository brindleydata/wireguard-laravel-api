<?php

use App\Exceptions\CommandFailedException;
use App\Services\Shell;

/*
 * The real Shell, running real (harmless) processes.
 */

it('passes bindings as single literal arguments', function () {
    $value = "it's; echo injected \$(id) `id`";

    expect((new Shell)->run('printf %s :value', ['value' => $value]))->toBe($value);
});

it('does not let shorter binding names clobber longer ones', function () {
    expect((new Shell)->run('printf "%s %s" :name :name_long', ['name' => 'a', 'name_long' => 'b']))->toBe('a b');
});

it('reports the exit code and stderr of a failed command', function () {
    try {
        (new Shell)->run('sh -c :script', ['script' => 'echo "sudo: a password is required" >&2; exit 3']);
        test()->fail('Expected the command to fail');
    } catch (CommandFailedException $e) {
        expect($e->exitCode)->toBe(3)
            ->and($e->getMessage())->toBe('Command failed with exit code 3: sudo: a password is required')
            ->and($e->context()['command'])->toContain('sh -c');
    }
});

it('runs commands from / whatever the caller\'s directory', function () {
    $here = getcwd();
    $dir = sys_get_temp_dir().'/wgla_cwd_'.bin2hex(random_bytes(4));
    mkdir($dir);
    chdir($dir);

    try {
        expect((new Shell)->run('pwd'))->toBe('/');
    } finally {
        chdir($here);
        rmdir($dir);
    }
});

it('returns null from tryRun when the command fails', function () {
    expect((new Shell)->tryRun('sh -c :script', ['script' => 'exit 1']))->toBeNull();
});

it('never binds a placeholder inside a value it has bound', function () {
    // Bound one after the other, ":key" inside the first value would be replaced by the second
    // value, quoted on its own: it would end up outside the first value's quotes
    expect((new Shell)->run('printf "%s|%s" :link :key', ['link' => 'a:key', 'key' => '$(echo injected)']))
        ->toBe('a:key|$(echo injected)');
});

it('leaves what is not a binding alone', function () {
    expect((new Shell)->run('printf %s :value:8080/:path', ['value' => 'host']))->toBe('host:8080/:path');
});
