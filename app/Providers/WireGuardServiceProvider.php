<?php

namespace App\Providers;

use App\Services\Host;
use App\Services\Link;
use App\Services\WireGuard;
use Illuminate\Support\ServiceProvider;

class WireGuardServiceProvider extends ServiceProvider
{
    public function register()
    {
        $app = $this->app;
        $app->singleton(Host::class, fn () => new Host);
        $app->singleton(Link::class, fn () => new Link($app->make(Host::class)));
        $app->singleton(WireGuard::class, fn () => new WireGuard(config('wireguard'), $app->make(Host::class)));
    }
}
