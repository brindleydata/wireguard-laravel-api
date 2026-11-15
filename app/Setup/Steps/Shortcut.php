<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * `wgla`: a shortcut for `php artisan wg:*` that runs each command as the user it belongs to.
 * `wgla link:create wg0 …` runs `wg:link:create` as the web user, `wgla update` runs `wg:update`
 * as the deploy user. The template is bin/wgla; it's rendered with this app's paths and users and
 * installed root-owned (root may run it), so the step re-installs it whenever those change.
 */
class Shortcut extends Step
{
    public const FILE = '/usr/local/bin/wgla';

    public const TEMPLATE = 'bin/wgla';

    public function key(): string
    {
        return 'shortcut';
    }

    public function title(): string
    {
        return 'The wgla command';
    }

    /**
     * bin/wgla with this server's values in place of its placeholders (shell-quoted).
     */
    public function script(Context $ctx): string
    {
        return strtr((string) file_get_contents($ctx->app(self::TEMPLATE)), [
            '@APP@' => self::q($ctx->app()),
            '@PHP@' => self::q($ctx->php),
            '@WEB@' => self::q($ctx->webUser()),
            '@DEPLOY@' => self::q($ctx->deployUser),
        ]);
    }

    public function check(Context $ctx): array
    {
        $file = $ctx->system(self::FILE);

        return is_file($file) && file_get_contents($file) === $this->script($ctx)
            ? []
            : [self::FILE.' is missing or out of date'];
    }

    public function plan(Context $ctx): array
    {
        $file = self::q($ctx->system(self::FILE));
        $dir = self::q(dirname($ctx->system(self::FILE)));

        return [Action::command(
            'Install it, owned by root',
            '(tmp=$(mktemp) && printf \'%s\' '.self::q($this->script($ctx)).' > "$tmp"'
            ." && sudo mkdir -p {$dir} && sudo install -o root -g {$ctx->rootGroup()} -m 755 \"\$tmp\" {$file}"
            .'; status=$?; rm -f "$tmp"; exit $status)',
        )];
    }
}
