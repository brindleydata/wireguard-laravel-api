<?php

namespace App\Providers;

use App\Services\InterfaceMap;
use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use App\Services\Os\OsDriver;
use App\Services\Shell;
use App\Services\WireGuard;
use App\Services\WireGuardSocket;
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

        $this->app->singleton(WireGuardSocket::class, fn () => new WireGuardSocket(
            socketDir: config('wireguard.socket_dir', '/var/run/wireguard'),
        ));

        $this->app->singleton(InterfaceMap::class, function () {
            $storagePath = storage_path('wireguard');
            if (! is_dir($storagePath)) {
                mkdir($storagePath, 0755, true);
            }

            return new InterfaceMap(
                mapFile: "{$storagePath}/interface-map.json",
            );
        });

        $this->app->singleton(WireGuard::class, function ($app) {
            $storagePath = storage_path('wireguard');
            if (! is_dir($storagePath)) {
                mkdir($storagePath, 0755, true);
            }

            return new WireGuard(
                config: config('wireguard'),
                shell: $app->make(Shell::class),
                os: $app->make(OsDriver::class),
                validator: $app->make(WireGuardValidator::class),
                socket: $app->make(WireGuardSocket::class),
                interfaceMap: $app->make(InterfaceMap::class),
                storagePath: $storagePath,
            );
        });
    }
}
