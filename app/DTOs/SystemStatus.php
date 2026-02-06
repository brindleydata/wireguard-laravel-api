<?php

namespace App\DTOs;

class SystemStatus
{
    public function __construct(
        public readonly array $app,
        public readonly array $cpu,
        public readonly array $ram,
        public readonly array $disk,
        public readonly string $endpoint,
    ) {}

    public function toArray(): array
    {
        return [
            'app' => $this->app,
            'cpu' => $this->cpu,
            'ram' => $this->ram,
            'disk' => $this->disk,
            'endpoint' => $this->endpoint,
        ];
    }
}
