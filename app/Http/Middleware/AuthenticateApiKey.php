<?php

namespace App\Http\Middleware;

use Illuminate\Auth\Middleware\Authenticate as Middleware;
use Closure;

class AuthenticateApiKey extends Middleware
{
    public function handle($request, Closure $next, ...$guards)
    {
        if ($request->header('api-key') !== env('API_KEY')) {
            return abort(403, 'Access denied.');
        }

        return $next($request);
    }
}
