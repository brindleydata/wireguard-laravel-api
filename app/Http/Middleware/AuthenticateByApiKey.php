<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateByApiKey
{
    public function handle(Request $request, Closure $next): Response
    {
        if (! hash_equals((string) config('wireguard.api_key'), (string) $request->header('api-key'))) {
            abort(403, 'Access denied.');
        }

        return $next($request);
    }
}
