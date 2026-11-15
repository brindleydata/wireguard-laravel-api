<?php

use App\Exceptions\ConflictException;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Http\Middleware\ForceJsonResponse;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Support\Env;
use Illuminate\Validation\ValidationException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

// .env values stay out of the process environment (no putenv). FrankenPHP keeps that environment
// across worker restarts, so `systemctl reload wgla` would otherwise keep serving the old values.
Env::disablePutenv();

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        api: __DIR__.'/../routes/api.php',
        commands: __DIR__.'/../routes/console.php',
        apiPrefix: '',
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->api(prepend: [
            ForceJsonResponse::class,
        ]);
        // A proxy on this host (--tls=http) passes the client's address on (X-Forwarded-For), so
        // the rate limit on wrong API keys counts per client, not all of them as the proxy
        $middleware->trustProxies(at: ['127.0.0.1', '::1']);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (NotFoundHttpException $e) {
            return response()->json(['error' => $e->getMessage() ?: 'Resource not found.'], 404);
        });

        $exceptions->render(function (NotFoundException $e) {
            return response()->json(['error' => $e->getMessage()], 404);
        });

        $exceptions->render(function (InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        });

        $exceptions->render(function (ConflictException $e) {
            return response()->json(['error' => $e->getMessage()], 409);
        });

        // Still reported to the log (with the command line for CommandFailedException)
        $exceptions->render(function (SystemException $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        });

        // The same shape for what the framework refuses itself. A request that fails its field
        // rules also lists every message per field.
        $exceptions->render(function (ValidationException $e) {
            return response()->json(['error' => $e->validator->errors()->first(), 'errors' => $e->errors()], $e->status);
        });

        $exceptions->render(function (HttpExceptionInterface $e) {
            return response()->json(['error' => $e->getMessage() ?: 'Request refused.'], $e->getStatusCode(), $e->getHeaders());
        });
    })->create();
