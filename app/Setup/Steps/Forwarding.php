<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Question;
use App\Setup\Step;

class Forwarding extends Step
{
    private const SYSCTL_FILE = '/etc/sysctl.d/99-wireguard.conf';

    public function key(): string
    {
        return 'forwarding';
    }

    public function title(): string
    {
        return 'IP forwarding';
    }

    public function questions(Context $ctx): array
    {
        return [new Question(
            key: 'forward',
            label: 'Will links route traffic for their peers (forward/NAT)?',
            type: 'confirm',
            default: true,
            hint: 'Needed for clients to reach other networks through the VPN; not for peer-to-server only.',
        )];
    }

    public function check(Context $ctx): array
    {
        if (! filter_var($ctx->answer('forward', true), FILTER_VALIDATE_BOOLEAN)) {
            return [];
        }

        if ($ctx->isMac()) {
            return $this->shell->tryRun('sysctl -n net.inet.ip.forwarding') === '1' ? [] : ['IP forwarding is off'];
        }

        $problems = [];
        if ($this->shell->tryRun('sysctl -n net.ipv4.ip_forward') !== '1') {
            $problems[] = 'IP forwarding is off';
        }
        $file = $ctx->system(self::SYSCTL_FILE);
        if (! is_file($file) || ! str_contains((string) file_get_contents($file), 'net.ipv4.ip_forward=1')) {
            $problems[] = 'IP forwarding is not kept across reboots';
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        if ($ctx->isMac()) {
            return [Action::command('Turn on IP forwarding (until the next reboot)', 'sudo sysctl -w net.inet.ip.forwarding=1')];
        }

        return [Action::command(
            'Turn on IP forwarding, also after reboots',
            "echo 'net.ipv4.ip_forward=1' | sudo tee ".self::q($ctx->system(self::SYSCTL_FILE)).' > /dev/null && sudo sysctl --system > /dev/null',
        )];
    }
}
