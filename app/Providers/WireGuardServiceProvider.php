<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use App\WireGuard\Service as wireGuard;

class WireGuardServiceProvider extends ServiceProvider
{
    /**
     * Register WireGuard application service.
     *
     * @return void
     */
    public function register()
    {
        $this->app->singleton(WireGuard::class, function () {
            return new WireGuard(config('wireguard'));
        });
    }
}
