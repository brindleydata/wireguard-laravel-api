<?php

namespace App\Providers;

use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use App\Services\Os\OsDriver;
use App\Services\Shell;
use App\Services\WireGuard;
use App\Validation\WireGuardValidator;
use Illuminate\Support\ServiceProvider;

class WireGuardServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->app->singleton(Shell::class, fn () => new Shell);

        $this->app->singleton(OsDriver::class, function ($app) {
            $shell = $app->make(Shell::class);

            return match (PHP_OS_FAMILY) {
                'Darwin' => new MacDriver($shell),
                default => new LinuxDriver($shell),
            };
        });

        $this->app->singleton(WireGuardValidator::class, fn () => new WireGuardValidator);

        $this->app->singleton(WireGuard::class, fn ($app) => new WireGuard(
            config: config('wireguard'),
            shell: $app->make(Shell::class),
            os: $app->make(OsDriver::class),
            validator: $app->make(WireGuardValidator::class),
        ));
    }
}
