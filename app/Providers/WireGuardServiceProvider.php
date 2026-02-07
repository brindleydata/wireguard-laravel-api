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
            socket_dir: config('wireguard.socket_dir', '/var/run/wireguard'),
        ));

        $this->app->singleton(InterfaceMap::class, function () {
            $storage_path = storage_path('wireguard');
            if (! is_dir($storage_path)) {
                mkdir($storage_path, 0755, true);
            }

            return new InterfaceMap(
                map_file: "{$storage_path}/interface-map.json",
            );
        });

        $this->app->singleton(WireGuard::class, function ($app) {
            $storage_path = storage_path('wireguard');
            if (! is_dir($storage_path)) {
                mkdir($storage_path, 0755, true);
            }

            return new WireGuard(
                config: config('wireguard'),
                os: $app->make(OsDriver::class),
                validator: $app->make(WireGuardValidator::class),
                socket: $app->make(WireGuardSocket::class),
                interface_map: $app->make(InterfaceMap::class),
                storage_path: $storage_path,
            );
        });
    }
}
