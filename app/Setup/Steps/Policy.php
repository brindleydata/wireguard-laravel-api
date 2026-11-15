<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Question;
use App\Setup\Step;

/**
 * What peers of any link may route on this server, as a ceiling the root helper enforces: a
 * default route (the server's own traffic would go through that peer), and networks that hold
 * the server's own addresses or its gateway (it could lose its own network). A link has to opt
 * in as well; this file says whether it may. Root's, so the web user can't raise it. A missing
 * file allows neither.
 */
class Policy extends Step
{
    public const FILE = '/etc/wgla/policy.conf';

    public function key(): string
    {
        return 'policy';
    }

    public function title(): string
    {
        return 'Route policy';
    }

    public function questions(Context $ctx): array
    {
        return [
            new Question(
                key: 'allow_default_route',
                label: 'May peers route a default route (0.0.0.0/0, ::/0)?',
                type: 'confirm',
                default: false,
                hint: "The server's own traffic would then go through that peer.",
            ),
            new Question(
                key: 'allow_own_networks',
                label: "May peers route networks that hold this server's own addresses or its gateway?",
                type: 'confirm',
                default: false,
                hint: 'The server could lose its own network.',
            ),
        ];
    }

    /** The file for the current answers: one key per line, true or false. */
    public function content(Context $ctx): string
    {
        $flag = fn (string $answer) => filter_var($ctx->answer($answer, false), FILTER_VALIDATE_BOOLEAN) ? 'true' : 'false';

        return "# Written by php artisan wg:install: what peers of any link may route (the root helper enforces it)\n"
            ."allow_default_route={$flag('allow_default_route')}\n"
            ."allow_own_networks={$flag('allow_own_networks')}\n";
    }

    public function check(Context $ctx): array
    {
        $file = $ctx->system(self::FILE);
        if (! is_file($file) || file_get_contents($file) !== $this->content($ctx)) {
            return [self::FILE.' is missing or out of date'];
        }

        // Whoever can change it decides what peers may route
        $dir = dirname($file);
        if (fileowner($file) !== 0 || (fileperms($file) & 0022) !== 0 || fileowner($dir) !== 0 || (fileperms($dir) & 0022) !== 0) {
            return [self::FILE.' and its directory must be owned by root and writable by nobody else'];
        }

        return [];
    }

    public function plan(Context $ctx): array
    {
        $file = self::q($ctx->system(self::FILE));
        $dir = self::q(dirname($ctx->system(self::FILE)));
        $owner = "-o root -g {$ctx->rootGroup()}";

        // install -d, not -D: macOS's install has no -D
        return [Action::command(
            'Write the policy, owned by root',
            '(tmp=$(mktemp) && printf \'%s\' '.self::q($this->content($ctx)).' > "$tmp"'
            ." && sudo install -d {$owner} -m 755 {$dir} && sudo install {$owner} -m 644 \"\$tmp\" {$file}"
            .'; status=$?; rm -f "$tmp"; exit $status)',
        )];
    }
}
