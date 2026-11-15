<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * Linux: a link's forward/NAT rules are installed when it starts. Another tool can take them
 * away later (`nft -f` of a ruleset that starts with "flush ruleset", a firewall restart), and
 * the link then stops routing without anything saying so. A systemd timer has the root helper
 * look every minute and put missing rules back. It needs neither the API nor PHP.
 */
class FirewallRepair extends Step
{
    public const SERVICE = '/etc/systemd/system/wgla-firewall.service';

    public const TIMER = '/etc/systemd/system/wgla-firewall.timer';

    public function key(): string
    {
        return 'firewall';
    }

    public function title(): string
    {
        return 'Firewall rules kept in place';
    }

    public function applies(Context $ctx): bool
    {
        return ! $ctx->isMac();
    }

    public function service(Context $ctx): string
    {
        return <<<UNIT
            [Unit]
            Description=WireGuard API: put back link firewall rules that another tool removed

            [Service]
            Type=oneshot
            ExecStart={$ctx->helperPath} firewall-repair
            # It runs every minute: only what it repairs (a warning) is worth a line in the journal
            LogLevelMax=notice

            UNIT;
    }

    public function timer(): string
    {
        return <<<'UNIT'
            [Unit]
            Description=WireGuard API: check the links' firewall rules every minute

            [Timer]
            OnBootSec=1min
            OnUnitActiveSec=1min
            AccuracySec=5s

            [Install]
            WantedBy=timers.target

            UNIT;
    }

    public function check(Context $ctx): array
    {
        $current = fn (string $path, string $content) => is_file($ctx->system($path)) && file_get_contents($ctx->system($path)) === $content;
        if (! $current(self::SERVICE, $this->service($ctx)) || ! $current(self::TIMER, $this->timer())) {
            return ['The timer that puts missing firewall rules back is not installed, or its settings changed'];
        }

        return $this->shell->tryRun('systemctl is-enabled wgla-firewall.timer') === 'enabled' && $this->shell->tryRun('systemctl is-active wgla-firewall.timer') === 'active'
            ? []
            : ['The timer that puts missing firewall rules back is not enabled and running'];
    }

    public function plan(Context $ctx): array
    {
        $service = self::q($ctx->system(self::SERVICE));
        $timer = self::q($ctx->system(self::TIMER));

        return [
            Action::command('Install the service and its timer', '(tmp=$(mktemp -d)'
                .' && printf \'%s\' '.self::q($this->service($ctx)).' > "$tmp/service" && printf \'%s\' '.self::q($this->timer()).' > "$tmp/timer"'
                ." && sudo install -o root -g root -m 644 \"\$tmp/service\" {$service} && sudo install -o root -g root -m 644 \"\$tmp/timer\" {$timer}"
                .'; status=$?; rm -rf "$tmp"; exit $status)'),
            Action::command('Start it now and at boot', 'sudo systemctl daemon-reload && sudo systemctl enable wgla-firewall.timer 2> /dev/null && sudo systemctl restart wgla-firewall.timer'),
        ];
    }
}
