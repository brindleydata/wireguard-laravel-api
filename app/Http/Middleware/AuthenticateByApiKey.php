<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Symfony\Component\HttpFoundation\Response;

class AuthenticateByApiKey
{
    /** Requests with a wrong (or no) API key one address may make in a minute; then 429 for a while. */
    public const ATTEMPTS = 10;

    public function handle(Request $request, Closure $next): Response
    {
        $key = (string) config('wireguard.api_key');
        // Per address (the client's behind a proxy on this host: bootstrap/app.php trusts it)
        $limiter = 'api-key:'.$request->ip();

        // So the key can't be guessed at speed. A right key doesn't get through either meanwhile:
        // the address is the guesser's
        if (RateLimiter::tooManyAttempts($limiter, self::ATTEMPTS)) {
            $wait = RateLimiter::availableIn($limiter);
            abort(429, "Too many requests with a wrong API key: try again in {$wait} s.", ['Retry-After' => (string) $wait]);
        }

        // Fail closed: with no API_KEY configured, an empty header would otherwise match
        if ($key === '' || ! hash_equals($key, (string) $request->header('api-key'))) {
            RateLimiter::hit($limiter, 60);
            abort(403, 'Access denied.');
        }

        return $next($request);
    }
}
