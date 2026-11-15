<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * The code belongs to the deploy user and is read-only for the web user, so a compromised web
 * process can't change the code it runs. Nor what the deploy user runs, who has sudo: artisan,
 * ./frankenphp, git's hooks in .git/. Only storage/ is writable for it.
 *
 * bootstrap/cache counts as code: it holds PHP files loaded at boot, and the deploy user must be
 * able to rebuild them (composer's package:discover clears them on every install).
 */
class Permissions extends Step
{
    private const WRITABLE = ['storage', 'storage/framework', 'storage/logs'];

    /** How many of the paths the web user can change a problem names. */
    private const NAMED = 5;

    public function key(): string
    {
        return 'permissions';
    }

    public function title(): string
    {
        return 'File ownership';
    }

    public function applies(Context $ctx): bool
    {
        return $ctx->separateWebUser();
    }

    public function check(Context $ctx): array
    {
        $web = $ctx->webUser();

        if (! $this->webUserCan($ctx, '-r', $ctx->app('artisan'))) {
            return ["{$web} can't read the app"];
        }

        $problems = [];
        foreach (self::WRITABLE as $dir) {
            if (! $this->webUserCan($ctx, '-w', $ctx->app($dir))) {
                $problems[] = "{$web} can't write {$dir}/";
            }
        }

        $changeable = $this->changeable($ctx);
        if ($changeable === null) {
            $problems[] = "It can't be told what {$web} can change in the app";
        } elseif ($changeable !== []) {
            $more = count($changeable) - self::NAMED;
            $problems[] = "{$web} can change the code: ".implode(', ', array_slice($changeable, 0, self::NAMED)).($more > 0 ? " and {$more} more" : '');
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        $app = self::q($ctx->app());
        $writable = self::q($ctx->app('storage'));
        $deploy = self::q("{$ctx->deployUser}:{$ctx->deployGroup}");
        $web = self::q("{$ctx->webUser()}:{$ctx->webGroup()}");

        return [
            Action::command("Give the code to {$ctx->deployUser}, not writable by others", "sudo chown -R {$deploy} {$app} && sudo chmod -R go-w {$app}"),
            Action::command("Let {$ctx->webUser()} write storage/", "sudo chown -R {$web} {$writable} && sudo chmod -R u+rwX {$writable}"),
        ];
    }

    public function manual(Context $ctx): string
    {
        return "Make sure {$ctx->webUser()} can reach {$ctx->app()} (its parent directories must be traversable).";
    }

    /**
     * Everything in the app but storage/ that the web user can change, relative to the app
     * (directories with a slash): what it owns (it could make that writable) and what it can
     * write. Listed by root, so no directory closed to the web user is left out, and tested as
     * the web user (`test -w`, which counts its groups and ACLs; BSD find has no -writable).
     * Symlinks are skipped: what counts is their target, found where it is. Null when it can't
     * be told.
     *
     * @return list<string>|null
     */
    protected function changeable(Context $ctx): ?array
    {
        $found = $this->asRoot('find :app -path :storage -prune -o ! -type l \( -user :user -print -o -exec sudo -n -u :user sh -c :test sh {} + \)', [
            'app' => $ctx->app(),
            'storage' => $ctx->app('storage'),
            'user' => $ctx->webUser(),
            // find fails when a batch does, which would otherwise be whenever its last file isn't writable
            'test' => 'for f do [ -w "$f" ] && printf \'%s\n\' "$f"; done; true',
        ]);
        if ($found === null) {
            return null;
        }

        // Sorted: what it owns is printed at once, what it can write by the batch
        $found = array_filter(explode("\n", $found));
        sort($found);

        return array_map(fn (string $path) => $path === $ctx->app()
            ? 'the app directory'
            : substr($path, strlen($ctx->app()) + 1).(is_dir($path) ? '/' : ''), $found);
    }
}
