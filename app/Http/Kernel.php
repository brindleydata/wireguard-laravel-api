<?php

namespace App\Http;

use App\Http\Middleware\AuthenticateApiKey;
use App\Http\Middleware\TrimStrings;
use Illuminate\Foundation\Http\Kernel as HttpKernel;
use Illuminate\Foundation\Http\Middleware\ConvertEmptyStringsToNull;

class Kernel extends HttpKernel
{
    /**
     * The application's global HTTP middleware stack.
     *
     * These middleware are run during every request to your application.
     *
     * @var array
     */
    protected $middleware = [
        TrimStrings::class,
        ConvertEmptyStringsToNull::class,
        AuthenticateApiKey::class,
    ];
}
