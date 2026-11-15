<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * Ubuntu (26.04 at least) confines wg-quick with an AppArmor profile that only lets it run a fixed
 * list of programs. The PostUp/PostDown hooks then can't run the root helper, and links with
 * forward or NAT fail to start ("wgla-helper: Permission denied"). The profile's extension point,
 * /etc/apparmor.d/local/wg-quick, gets one rule: run the helper unconfined (it validates its own
 * input). The profile is compiled with the rule before it's reloaded (only if it's loaded at all);
 * a rejected rule is rolled back.
 */
class AppArmor extends Step
{
    private const PROFILE = '/etc/apparmor.d/wg-quick';

    private const LOCAL = '/etc/apparmor.d/local/wg-quick';

    public function key(): string
    {
        return 'apparmor';
    }

    public function title(): string
    {
        return 'AppArmor rule for wg-quick';
    }

    public function applies(Context $ctx): bool
    {
        return ! $ctx->isMac() && is_file($ctx->system(self::PROFILE));
    }

    public function rule(Context $ctx): string
    {
        return "{$ctx->helperPath} Ux,";
    }

    public function check(Context $ctx): array
    {
        $local = $ctx->system(self::LOCAL);
        $lines = is_file($local) ? array_map('trim', file($local)) : [];

        return in_array($this->rule($ctx), $lines, true)
            ? []
            : ["AppArmor doesn't let wg-quick run the root helper: links with forward or NAT can't start"];
    }

    public function plan(Context $ctx): array
    {
        $profile = self::q($ctx->system(self::PROFILE));
        $local = self::q($ctx->system(self::LOCAL));
        $lines = self::q('# Lets wg-quick run the WireGuard API root helper from PostUp/PostDown (php artisan wg:install)')
            .' '.self::q($this->rule($ctx));

        return [Action::command(
            'Add the rule to the local override, check the profile compiles, then reload it',
            '(backup=$(mktemp) && tmp=$(mktemp)'
            ." && { sudo cat {$local} > \"\$backup\" 2> /dev/null || : > \"\$backup\"; }"
            ." && { cat \"\$backup\"; printf '%s\\n' {$lines}; } > \"\$tmp\""
            ." && sudo install -D -o root -g root -m 644 \"\$tmp\" {$local}"
            ." && if sudo apparmor_parser -Q {$profile} > /dev/null 2>&1; then"
            // Reload only a loaded profile: one the admin disabled stays unloaded
            ." if sudo grep -qs '^wg-quick ' /sys/kernel/security/apparmor/profiles; then sudo apparmor_parser -r {$profile}; fi;"
            ." else sudo install -o root -g root -m 644 \"\$backup\" {$local}; echo 'apparmor_parser rejected the rule; nothing changed' >&2; false; fi"
            .'; status=$?; rm -f "$tmp" "$backup"; exit $status)',
        )];
    }
}
