<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * The code belongs to the deploy user and is read-only for the web user, so a compromised web
 * process can't change the code it runs. Only storage/ is writable for it.
 *
 * bootstrap/cache counts as code: it holds PHP files loaded at boot, and the deploy user must be
 * able to rebuild them (composer's package:discover clears them on every install).
 */
class Permissions extends Step
{
    private const WRITABLE = ['storage', 'storage/framework', 'storage/logs'];

    private const READ_ONLY = ['', 'app', 'bin', 'bootstrap/cache', 'config', 'public', 'routes', 'vendor'];

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
        foreach (self::READ_ONLY as $dir) {
            if ($this->webUserCan($ctx, '-w', $ctx->app($dir))) {
                $problems[] = "{$web} can change the code in ".($dir === '' ? 'the app directory' : "{$dir}/");
            }
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
}
