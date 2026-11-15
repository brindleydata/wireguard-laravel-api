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

    /**
     * How many commits $commit is ahead of $base, when $base is one of its ancestors (0 when they
     * are the same); null when it isn't (behind, or another line of history), or git can't say.
     */
    public function ahead(Context $ctx, string $base, string $commit): ?int
    {
        // "<only in base>\t<only in commit>"
        $counts = $this->git($ctx, 'rev-list --left-right --count :range', ['range' => "{$base}...{$commit}"]);

        return $counts !== null && preg_match('/^0\s+(\d+)$/', $counts, $m) ? (int) $m[1] : null;
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

    /**
     * Files that moving from one commit to another changes in directories the deploy user can't
     * write (storage/ is the web user's), with that directory: git would leave such a checkout
     * half done, and might not even say so.
     *
     * @return array<string, string> path => the directory in the way
     */
    public function unwritable(Context $ctx, string $from, string $to): array
    {
        $changed = $this->git($ctx, 'diff --name-only --no-renames -z :from :to', ['from' => $from, 'to' => $to]);

        $blocked = [];
        foreach (array_filter(explode("\0", (string) $changed)) as $path) {
            // In a new directory: whoever creates it writes into its nearest existing parent
            $dir = dirname($ctx->app($path));
            while (! is_dir($dir) && strlen($dir) > strlen($ctx->app())) {
                $dir = dirname($dir);
            }
            if (! is_writable($dir)) {
                $blocked[$path] = $dir;
            }
        }

        return $blocked;
    }

    /**
     * Record an update before it changes anything: the commit it starts from, the one it goes to
     * and the FrankenPHP binary from before (a hash). Until end() removes the record the update
     * isn't over, so one that was interrupted (Ctrl-C, a dropped SSH session) can't pass for done:
     * the next wg:update goes back first. Null when it can't be recorded.
     *
     * @return array{from: string, to: string, frankenphp: ?string}|null
     */
    public function begin(Context $ctx, string $from, string $to): ?array
    {
        $path = $this->recordPath($ctx);
        $update = ['from' => $from, 'to' => $to, 'frankenphp' => $this->frankenPhp($ctx)];

        // Whole or not at all
        return $path !== null && @file_put_contents("{$path}.tmp", json_encode($update)."\n") !== false && @rename("{$path}.tmp", $path)
            ? $update : null;
    }

    /**
     * The update that began and never ended, as begin() recorded it, or null. A record that can't
     * be read comes back without its commits.
     *
     * @return array{from: ?string, to: ?string, frankenphp: ?string}|null
     */
    public function unfinished(Context $ctx): ?array
    {
        $path = $this->recordPath($ctx);
        if ($path === null || ! is_file($path)) {
            return null;
        }

        $record = json_decode((string) file_get_contents($path), true);
        $field = fn (string $key, string $pattern) => is_string($record[$key] ?? null) && preg_match($pattern, $record[$key]) ? $record[$key] : null;

        return ['from' => $field('from', '/^[0-9a-z]+$/'), 'to' => $field('to', '/^[0-9a-z]+$/'), 'frankenphp' => $field('frankenphp', '/^[0-9a-f]+$/')];
    }

    /** The update is over (done, or gone back from): its record goes. */
    public function end(Context $ctx): bool
    {
        $path = $this->recordPath($ctx);

        return $path !== null && (! file_exists($path) || unlink($path));
    }

    /**
     * Where an update in progress is recorded: in git's directory, which is the deploy user's and
     * not part of the checkout. Null when git can't say.
     */
    public function recordPath(Context $ctx): ?string
    {
        $path = $this->git($ctx, 'rev-parse --git-path wgla-update');

        // Relative to the app, which git ran in
        return $path === null || $path === '' ? null : (str_starts_with($path, '/') ? $path : $ctx->app($path));
    }

    /**
     * Check out a commit. Whether that worked is what the work tree says, not git's exit status:
     * git exits 0 when it could only warn that it couldn't replace a file (the checkout is half
     * done), and 1 when it warned the same going back to the file it had left (all is in place).
     * $force (going back) discards what a failed checkout left half done; an update starts from a
     * clean checkout, so there is nothing else to discard.
     */
    public function checkout(Context $ctx, string $commit, bool $force = false): bool
    {
        $this->shell->interactive('git -C '.escapeshellarg($ctx->app()).' checkout --quiet '.($force ? '--force ' : '').'--detach '.escapeshellarg($commit));

        return $this->commit($ctx, 'HEAD') === $commit
            && $this->git($ctx, 'status --porcelain --untracked-files=no') === '';
    }

    public function composerInstall(Context $ctx): bool
    {
        return $this->shell->interactive('composer install --no-dev --optimize-autoloader --no-interaction --quiet --working-dir='.escapeshellarg($ctx->app())) === 0;
    }

    /**
     * Run $command (Steps\Server::downloadFrankenPhp()) to fetch the current FrankenPHP release.
     * True when the binary changed, false when it was current already, null when the download
     * failed and the installed one is still there.
     */
    public function refreshFrankenPhp(Context $ctx, string $command): ?bool
    {
        $before = $this->frankenPhp($ctx);

        if ($this->shell->interactive($command) !== 0 || ($after = $this->frankenPhp($ctx)) === null) {
            return null;
        }

        return $after !== $before;
    }

    /**
     * Put the FrankenPHP binary from before an update ($before, as begin() recorded it) back when
     * the update replaced it: the download kept it as frankenphp.previous. True when it was put
     * back, false when there was nothing to put back, null when it can't be (it's gone).
     */
    public function restoreFrankenPhp(Context $ctx, ?string $before): ?bool
    {
        if ($before === null || $this->frankenPhp($ctx) === $before) {
            return false;
        }
        $previous = $ctx->app('frankenphp.previous');

        return is_file($previous) && hash_file('xxh128', $previous) === $before && rename($previous, $ctx->app('frankenphp')) ? true : null;
    }

    /** The installed FrankenPHP binary (a hash), or null when there is none. */
    protected function frankenPhp(Context $ctx): ?string
    {
        $binary = $ctx->app('frankenphp');
        clearstatcache(true, $binary);

        return is_file($binary) ? hash_file('xxh128', $binary) : null;
    }

    /** A new FrankenPHP binary only runs after a restart: a reload keeps the old process. */
    public function restartApi(): bool
    {
        return $this->shell->interactive('sudo systemctl restart wgla') === 0;
    }

    /** One run of what the repair timer runs (the helper's firewall-repair, as root). */
    public function repairFirewall(): bool
    {
        return $this->shell->interactive('sudo systemctl start wgla-firewall.service') === 0;
    }

    /**
     * Run `wg:update --finish` with the code now on disk, in a new process. $back: as the way back
     * from a failed update.
     */
    public function finish(Context $ctx, string $from, bool $yes, bool $back = false): bool
    {
        return $this->update($ctx, ['finish' => $from, 'back' => $back, 'yes' => $yes]);
    }

    /**
     * Run `wg:update` with the code now on disk, in a new process.
     *
     * @param  array<string, string|bool|null>  $options  --name=value, or --name for true; false and null leave it out
     */
    public function update(Context $ctx, array $options = []): bool
    {
        $command = escapeshellarg($ctx->php).' '.escapeshellarg($ctx->app('artisan')).' wg:update';
        foreach ($options as $name => $value) {
            $command .= match (true) {
                is_string($value) => " --{$name}=".escapeshellarg($value),
                $value === true => " --{$name}",
                default => '',
            };
        }

        return $this->shell->interactive($command) === 0;
    }

    protected function git(Context $ctx, string $command, array $bindings = []): ?string
    {
        return $this->shell->tryRun("git -C :app {$command}", ['app' => $ctx->app(), ...$bindings]);
    }
}
