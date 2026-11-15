<?php

namespace App\Setup;

use Closure;

/**
 * One fix. Usually a shell command with explicit `sudo` where root is needed, so the admin sees
 * exactly what runs (and `wg:install --print` can output it); a few are PHP code that runs as
 * the installer user, such as editing .env.
 */
final class Action
{
    private function __construct(
        public readonly string $description,
        public readonly ?string $command = null,
        public readonly ?Closure $callback = null,
    ) {}

    public static function command(string $description, string $command): self
    {
        return new self($description, command: $command);
    }

    /**
     * @param  Closure(Context): void  $callback
     */
    public static function php(string $description, Closure $callback): self
    {
        return new self($description, callback: $callback);
    }
}
