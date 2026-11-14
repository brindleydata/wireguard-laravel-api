<?php

namespace App\Setup;

use App\Services\Shell;

/**
 * Git and Composer for `wg:update`. The app is a git checkout owned by the deploy user; updates
 * move it to a release tag (vX.Y.Z), or to a branch head for testing.
 */
class Updater
{
    public function __construct(protected Shell $shell) {}

    public function isCheckout(Context $ctx): bool
    {
        return $this->git($ctx, 'rev-parse --is-inside-work-tree') === 'true';
    }

    /** @return list<string> tracked files with local changes (git status lines) */
    public function localChanges(Context $ctx): array
    {
        $status = $this->git($ctx, 'status --porcelain --untracked-files=no');

        return $status === null || $status === '' ? [] : explode("\n", $status);
    }

    public function fetch(Context $ctx): bool
    {
        return $this->git($ctx, 'fetch --quiet --tags --prune --force origin') !== null;
    }

    /**
     * The newest release tag (vX.Y.Z), or null when there is none. Pre-releases (v1.2.0-rc1)
     * don't count: git sorts them above the release they lead up to. `--to=` still takes one.
     */
    public function latestRelease(Context $ctx): ?string
    {
        $tags = (string) $this->git($ctx, "tag --list 'v[0-9]*' --sort=-v:refname");

        return array_find(explode("\n", $tags), fn (string $tag) => preg_match('/^v\d+(\.\d+)*$/', $tag) === 1);
    }

    /** The commit a ref (tag, branch, sha) points to, or null when it doesn't exist. */
    public function commit(Context $ctx, string $ref): ?string
    {
        return $this->git($ctx, 'rev-parse --verify --quiet :ref', ['ref' => "{$ref}^{commit}"]);
    }

    /** A readable name for a commit: its release tag, else a short hash. */
    public function name(Context $ctx, string $commit): string
    {
        return $this->git($ctx, 'describe --tags --exact-match :commit', ['commit' => $commit])
            ?? (string) $this->git($ctx, 'rev-parse --short :commit', ['commit' => $commit]);
    }

    public function changelog(Context $ctx, string $from, string $to): string
    {
        return (string) $this->git($ctx, 'log --oneline --no-decorate :range', ['range' => "{$from}..{$to}"]);
    }

    /** Changes to the root helper between two commits: it runs as root, so updates show them. */
    public function helperDiff(Context $ctx, string $from, string $to): string
    {
        return (string) $this->git($ctx, 'diff :from :to -- bin/wgla-helper', ['from' => $from, 'to' => $to]);
    }

    public function checkout(Context $ctx, string $commit): bool
    {
        return $this->shell->interactive('git -C '.escapeshellarg($ctx->app()).' checkout --quiet --detach '.escapeshellarg($commit)) === 0;
    }

    public function composerInstall(Context $ctx): bool
    {
        return $this->shell->interactive('composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='.escapeshellarg($ctx->app())) === 0;
    }

    /**
     * Run $command (Steps\Server::replaceFrankenPhp()) to fetch the current FrankenPHP release.
     * True when the binary changed, false when it was current already, null when the download
     * failed and the installed one is still there.
     */
    public function refreshFrankenPhp(Context $ctx, string $command): ?bool
    {
        $binary = $ctx->app('frankenphp');
        $before = is_file($binary) ? hash_file('sha256', $binary) : null;

        if ($this->shell->interactive($command) !== 0 || ! is_file($binary)) {
            return null;
        }
        clearstatcache(true, $binary);

        return hash_file('sha256', $binary) !== $before;
    }

    /** A new FrankenPHP binary only runs after a restart: a reload keeps the old process. */
    public function restartApi(): bool
    {
        return $this->shell->interactive('sudo systemctl restart wgla') === 0;
    }

    /** Run `wg:update --finish` with the code now on disk, in a new process. */
    public function finish(Context $ctx, string $from, bool $yes): bool
    {
        return $this->shell->interactive(
            escapeshellarg($ctx->php).' '.escapeshellarg($ctx->app('artisan')).' wg:update --finish='.escapeshellarg($from).($yes ? ' --yes' : '')
        ) === 0;
    }

    protected function git(Context $ctx, string $command, array $bindings = []): ?string
    {
        return $this->shell->tryRun("git -C :app {$command}", ['app' => $ctx->app(), ...$bindings]);
    }
}
