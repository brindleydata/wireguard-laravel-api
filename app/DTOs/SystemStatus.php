<?php

namespace App\DTOs;

class SystemStatus
{
    public function __construct(
        public readonly array $app,
        public readonly array $cpu,
        public readonly array $ram,
        public readonly array $disk,
        public readonly string $hostname,
        public readonly array $helper = [],
    ) {}

    public function toArray(): array
    {
        return [
            'app' => $this->app,
            'cpu' => $this->cpu,
            'ram' => $this->ram,
            'disk' => $this->disk,
            'hostname' => $this->hostname,
            'helper' => $this->helper,
        ];
    }
}
