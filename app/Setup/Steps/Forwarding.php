<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Question;
use App\Setup\Step;

/**
 * IP forwarding for both families (IPv6 only where the kernel has it), kept across reboots.
 *
 * With IPv6 forwarding on, the kernel ignores router advertisements on interfaces where it
 * handles them itself (accept_ra = 1, e.g. ifupdown with SLAAC): a server that learns its IPv6
 * default route that way would lose it. That interface gets accept_ra = 2, which keeps them.
 * systemd-networkd and NetworkManager handle router advertisements themselves (accept_ra = 0)
 * and keep working.
 */
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
            $problems = [];
            if ($this->shell->tryRun('sysctl -n net.inet.ip.forwarding') !== '1') {
                $problems[] = 'IP forwarding is off';
            }
            if ($this->shell->tryRun('sysctl -n net.inet6.ip6.forwarding') === '0') {
                $problems[] = 'IPv6 forwarding is off';
            }

            return $problems;
        }

        $problems = [];
        $saved = $this->savedLines($ctx);
        if ($this->shell->tryRun('sysctl -n net.ipv4.ip_forward') !== '1') {
            $problems[] = 'IP forwarding is off';
        }
        if (! in_array('net.ipv4.ip_forward=1', $saved, true)) {
            $problems[] = 'IP forwarding is not kept across reboots';
        }

        $ipv6 = $this->shell->tryRun('sysctl -n net.ipv6.conf.all.forwarding');
        if ($ipv6 !== null) {
            if ($ipv6 !== '1') {
                $problems[] = 'IPv6 forwarding is off';
            }
            if (! in_array('net.ipv6.conf.all.forwarding=1', $saved, true)) {
                $problems[] = 'IPv6 forwarding is not kept across reboots';
            }
            $uplink = $this->ipv6Uplink();
            if ($uplink !== null && $this->acceptRa($uplink) === '1') {
                $problems[] = "{$uplink} learns its IPv6 route from router advertisements, which IPv6 forwarding would turn off";
            }
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        if ($ctx->isMac()) {
            $command = 'sudo sysctl -w net.inet.ip.forwarding=1';
            if ($this->shell->tryRun('sysctl -n net.inet6.ip6.forwarding') !== null) {
                $command .= ' net.inet6.ip6.forwarding=1';
            }

            return [Action::command('Turn on IP forwarding (until the next reboot)', $command)];
        }

        $lines = ['net.ipv4.ip_forward=1'];
        if ($this->shell->tryRun('sysctl -n net.ipv6.conf.all.forwarding') !== null) {
            $lines[] = 'net.ipv6.conf.all.forwarding=1';
            // Keep router advertisements where the kernel handles them (and keep a line added before)
            $uplink = $this->ipv6Uplink();
            $ra = $uplink === null ? null : "net/ipv6/conf/{$uplink}/accept_ra=2";
            if ($ra !== null && ($this->acceptRa($uplink) === '1' || in_array($ra, $this->savedLines($ctx), true))) {
                $lines[] = $ra;
            }
        }

        return [Action::command(
            count($lines) > 1 ? 'Turn on IPv4 and IPv6 forwarding, also after reboots' : 'Turn on IP forwarding, also after reboots',
            'printf \'%s\n\' '.implode(' ', array_map(self::q(...), $lines)).' | sudo tee '.self::q($ctx->system(self::SYSCTL_FILE)).' > /dev/null && sudo sysctl --system > /dev/null',
        )];
    }

    /** @return list<string> settings in our sysctl file, without spaces */
    protected function savedLines(Context $ctx): array
    {
        $file = $ctx->system(self::SYSCTL_FILE);

        return is_file($file) ? array_map(fn (string $line) => str_replace(' ', '', trim($line)), file($file)) : [];
    }

    /** The interface of the IPv6 default route, if there is one. */
    protected function ipv6Uplink(): ?string
    {
        $route = $this->shell->tryRun('ip -6 route show default');

        return $route !== null && preg_match('/\bdev\s+([A-Za-z0-9_.@-]{1,15})\b/', $route, $m) ? explode('@', $m[1])[0] : null;
    }

    protected function acceptRa(string $interface): ?string
    {
        return $this->shell->tryRun('cat :file', ['file' => "/proc/sys/net/ipv6/conf/{$interface}/accept_ra"]);
    }
}
