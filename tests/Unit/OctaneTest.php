<?php

/*
 * `octane:install --server=frankenphp` appends entries to .gitignore when they're missing. The
 * installer downloads FrankenPHP itself and doesn't run it, but an admin may: that would leave
 * the deploy checkout with a local change, and wg:update refuses to update over local changes.
 * So .gitignore must already have everything Octane adds.
 */

it('has every .gitignore entry octane:install would add', function () {
    $source = (string) file_get_contents(__DIR__.'/../../vendor/laravel/octane/src/Commands/InstallCommand.php');

    // The list in InstallCommand::installFrankenPhpServer()
    expect(preg_match('/function installFrankenPhpServer\(\).*?collect\(\[(.*?)\]\)/s', $source, $match))->toBe(1, "Octane's installer changed: re-check what it writes");
    preg_match_all("/'([^']+)'/", $match[1], $entries);

    $gitignore = (string) file_get_contents(__DIR__.'/../../.gitignore');

    expect($entries[1])->not->toBeEmpty();
    foreach ($entries[1] as $entry) {
        // Octane's own check: str_contains($contents, $entry.PHP_EOL)
        expect(str_contains($gitignore, $entry.PHP_EOL))->toBeTrue("octane:install would add {$entry} to .gitignore");
    }
});
