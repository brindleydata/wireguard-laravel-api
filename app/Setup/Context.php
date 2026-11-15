<?php

namespace App\Setup;

/**
 * What the installer knows about this machine, plus what the admin answered so far.
 */
final class Context
{
    /**
     * @param  string  $deployUser  Runs the installer and owns the code; the API runs as the web user
     * @param  string  $php  PHP binary the service runs artisan with
     * @param  string  $root  Filesystem prefix for system paths (/etc/…); only tests set it
     * @param  array<string, mixed>  $answers
     */
    public function __construct(
        public readonly string $os,
        public readonly string $appPath,
        public readonly string $deployUser,
        public readonly string $deployGroup,
        public readonly string $php,
        public readonly string $helperPath,
        public readonly string $bundledHelper,
        public readonly string $root = '',
        public array $answers = [],
    ) {}

    public function isMac(): bool
    {
        return $this->os === 'mac';
    }

    public function answer(string $key, mixed $default = null): mixed
    {
        $value = $this->answers[$key] ?? null;

        return $value === null || $value === '' ? $default : $value;
    }

    public function webUser(): string
    {
        return (string) $this->answer('web_user', $this->deployUser);
    }

    public function webGroup(): string
    {
        return (string) $this->answer('web_group', $this->webUser());
    }

    /** The API runs as a different user than the one owning the code (the production setup). */
    public function separateWebUser(): bool
    {
        return $this->webUser() !== $this->deployUser;
    }

    public function rootGroup(): string
    {
        return $this->isMac() ? 'wheel' : 'root';
    }

    /** A path inside the app. */
    public function app(string $relative = ''): string
    {
        return $relative === '' ? $this->appPath : "{$this->appPath}/{$relative}";
    }

    /** A system path such as /etc/sudoers.d/wgla (prefixed in tests). */
    public function system(string $path): string
    {
        return $this->root.$path;
    }
}
