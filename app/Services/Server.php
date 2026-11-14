<?php

namespace App\Services;

use App\DTOs\SystemStatus;
use App\Services\Os\OsDriver;

class Server
{
    public function __construct(
        protected OsDriver $os,
    ) {}

    public function status(): SystemStatus
    {
        $hostname = config('wireguard.hostname') ?? gethostname();

        return new SystemStatus(
            app: [
                'name' => config('app.name'),
                'version' => config('app.version', '0.0'),
            ],
            cpu: $this->os->cpu(),
            ram: $this->os->ram(),
            disk: $this->os->disk(),
            hostname: $hostname,
            helper: $this->os->helperStatus(),
        );
    }

    public function ip(): array
    {
        $ip_service = config('wireguard.ip_service', 'http://ifconfig.me/ip');

        return [
            'ipv4' => $this->os->publicIpv4($ip_service),
            'ipv6' => $this->os->publicIpv6($ip_service),
        ];
    }

    /** The user this process runs as. */
    public function processUser(): string
    {
        return function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '') : get_current_user();
    }

    /** Whether the API can do its job: the root helper is installed, current and allowed by sudo. */
    public function healthy(): bool
    {
        return $this->os->helperStatus()['state'] === 'ok';
    }

    public function interfaces(): array
    {
        return $this->os->networkInterfaces();
    }
}
