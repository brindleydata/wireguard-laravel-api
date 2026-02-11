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

    public function interfaces(): array
    {
        return $this->os->networkInterfaces();
    }
}
