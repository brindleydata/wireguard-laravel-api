<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateByApiKey
{
    public function handle(Request $request, Closure $next): Response
    {
        $key = (string) config('wireguard.api_key');

        // Fail closed: with no API_KEY configured, an empty header would otherwise match
        if ($key === '' || ! hash_equals($key, (string) $request->header('api-key'))) {
            abort(403, 'Access denied.');
        }

        return $next($request);
    }
}
