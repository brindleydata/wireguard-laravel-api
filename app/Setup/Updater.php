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

    /** The newest release tag (vX.Y.Z), or null when there is none. */
    public function latestRelease(Context $ctx): ?string
    {
        $tags = $this->git($ctx, "tag --list 'v[0-9]*' --sort=-v:refname");

        return $tags === null || $tags === '' ? null : explode("\n", $tags)[0];
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
