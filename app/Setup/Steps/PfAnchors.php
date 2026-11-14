<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * macOS: pf only evaluates the per-link wg/<link> anchors if /etc/pf.conf references them. They
 * go right after Apple's own anchors: pf rejects translation (nat-anchor) rules that come after
 * filter (anchor) rules, which is why simply appending them to the file fails.
 */
class PfAnchors extends Step
{
    private const PF_CONF = '/etc/pf.conf';

    /** Drop our lines wherever they are (also from the old append-at-the-end instructions), re-insert them after Apple's. */
    private const AWK = '!/^(nat-)?anchor "wg\/\*"$/ && !/^# WireGuard NAT anchors$/ { print } '
        .'/^nat-anchor "com\.apple\/\*"$/ { print "nat-anchor \"wg/*\"" } '
        .'/^anchor "com\.apple\/\*"$/ { print "anchor \"wg/*\"" }';

    public function key(): string
    {
        return 'pf';
    }

    public function title(): string
    {
        return 'pf anchors (macOS)';
    }

    public function applies(Context $ctx): bool
    {
        return $ctx->isMac();
    }

    public function check(Context $ctx): array
    {
        $file = $ctx->system(self::PF_CONF);
        $content = is_file($file) ? (string) file_get_contents($file) : '';

        if (! preg_match('/^nat-anchor "wg\/\*"$/m', $content) || ! preg_match('/^anchor "wg\/\*"$/m', $content)) {
            return [self::PF_CONF.' does not load the wg/* anchors'];
        }
        if ($this->shell->tryRun('pfctl -n -f :file', ['file' => $file]) === null) {
            return [self::PF_CONF.' has the wg/* anchors in a position pf rejects'];
        }

        return [];
    }

    public function plan(Context $ctx): array
    {
        $conf = self::q($ctx->system(self::PF_CONF));
        $backup = self::q($ctx->system(self::PF_CONF.'.wgla-backup'));

        return [Action::command(
            'Add the anchors after Apple\'s, check the result with pfctl, back up and load it',
            '(tmp=$(mktemp) && awk '.self::q(self::AWK)." {$conf} > \"\$tmp\""
            .' && grep -q \'^nat-anchor "wg/\*"$\' "$tmp" && pfctl -n -f "$tmp" 2>/dev/null'
            ." && sudo cp {$conf} {$backup} && sudo install -o root -g wheel -m 644 \"\$tmp\" {$conf}"
            ." && sudo pfctl -f {$conf} 2>/dev/null; status=\$?; rm -f \"\$tmp\"; exit \$status)",
        )];
    }

    public function manual(Context $ctx): string
    {
        return 'Add nat-anchor "wg/*" after the other nat-anchor lines and anchor "wg/*" after the other anchor lines in '
            .self::PF_CONF.', then run: sudo pfctl -f '.self::PF_CONF;
    }
}
