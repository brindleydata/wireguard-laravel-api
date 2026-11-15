<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * One line, no argument wildcards (sudo-rs rejects them): the web user may run the helper as
 * root, nothing else. The file is checked with visudo before it is installed, because a broken
 * file in /etc/sudoers.d can lock everyone out of sudo.
 */
class Sudoers extends Step
{
    private const FILE = '/etc/sudoers.d/wgla';

    public function key(): string
    {
        return 'sudoers';
    }

    public function title(): string
    {
        return 'sudo rule for the helper';
    }

    public function line(Context $ctx): string
    {
        return "{$ctx->webUser()} ALL=(root) NOPASSWD: {$ctx->helperPath}";
    }

    public function check(Context $ctx): array
    {
        $current = $this->asRoot('cat :file', ['file' => $ctx->system(self::FILE)]);

        return $current === $this->line($ctx) ? [] : [self::FILE.' does not contain: '.$this->line($ctx)];
    }

    public function plan(Context $ctx): array
    {
        $file = self::q($ctx->system(self::FILE));

        return [Action::command(
            'Write the rule, check it with visudo, then install it',
            '(tmp=$(mktemp) && printf \'%s\n\' '.self::q($this->line($ctx)).' > "$tmp"'
            .' && sudo visudo -cf "$tmp" > /dev/null && sudo install -o root -g '.$ctx->rootGroup()." -m 440 \"\$tmp\" {$file}"
            .'; status=$?; rm -f "$tmp"; exit $status)',
        )];
    }
}
