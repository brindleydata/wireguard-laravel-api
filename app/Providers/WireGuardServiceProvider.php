<?php

namespace App\Providers;

use App\Services\Backup;
use App\Services\ConfigBuilder;
use App\Services\IpAllocator;
use App\Services\KeyManager;
use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use App\Services\Os\OsDriver;
use App\Services\Server;
use App\Services\Shell;
use App\Services\WireGuard;
use App\Validation\WireGuardValidator;
use Illuminate\Support\ServiceProvider;

class WireGuardServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        // Without resolving any service: tests (and the container) may still swap them
        Server::rememberRunningCode(base_path());
    }

    public function register(): void
    {
        $this->app->singleton(Shell::class, fn () => new Shell);

        $this->app->singleton(OsDriver::class, function ($app) {
            $shell = $app->make(Shell::class);

            $helper = config('wireguard.helper');
            $bundled = base_path('bin/wgla-helper');

            return match (PHP_OS_FAMILY) {
                'Darwin' => new MacDriver($shell, $helper, $bundled),
                default => new LinuxDriver($shell, $helper, $bundled),
            };
        });

        $this->app->singleton(WireGuardValidator::class, fn () => new WireGuardValidator);

        $this->app->singleton(KeyManager::class, fn () => new KeyManager);

        $this->app->singleton(IpAllocator::class, fn () => new IpAllocator);

        $this->app->singleton(ConfigBuilder::class, fn ($app) => new ConfigBuilder(
            config: config('wireguard'),
            os: $app->make(OsDriver::class),
        ));

        $this->app->singleton(Server::class, fn ($app) => new Server(
            os: $app->make(OsDriver::class),
        ));

        $this->app->singleton(WireGuard::class, fn ($app) => new WireGuard(
            config: config('wireguard'),
            os: $app->make(OsDriver::class),
            validator: $app->make(WireGuardValidator::class),
            keys: $app->make(KeyManager::class),
            configBuilder: $app->make(ConfigBuilder::class),
            ipAllocator: $app->make(IpAllocator::class),
            lockPath: storage_path('framework/locks'),
        ));

        $this->app->singleton(Backup::class, fn ($app) => new Backup(
            wg: $app->make(WireGuard::class),
            configBuilder: $app->make(ConfigBuilder::class),
            config: config('wireguard'),
            appVersion: (string) config('app.version'),
        ));
    }
}
