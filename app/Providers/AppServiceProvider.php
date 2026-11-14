<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        //
    }

    public function boot(): void
    {
        // storage/ belongs to the web user. When the deploy user runs artisan (wg:install,
        // wg:update, composer's package:discover), log to the terminal instead of failing to
        // open the log file and hiding the real error.
        if ($this->app->runningInConsole() && ! is_writable(storage_path('logs'))) {
            config(['logging.default' => 'stderr']);
        }
    }
}
