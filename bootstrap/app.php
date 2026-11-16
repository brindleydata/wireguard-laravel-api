<?php

use App\Exceptions\ConflictException;
use App\Exceptions\ErrorCode;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Http\Middleware\ForceJsonResponse;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Http\Exceptions\HttpResponseException;
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
        // Every error is {"error": …, "code": …}: a message for people, and a code that stays the
        // same for clients (App\Exceptions\ErrorCode), whoever refuses the request
        $error = fn (Throwable $e, int $status, ?string $message = null, array $more = [], array $headers = []) => response()->json(
            ['error' => $message ?? $e->getMessage(), 'code' => ErrorCode::of($e), ...$more], $status, $headers,
        );

        // A link or a peer that isn't there: `link_not_found`, `peer_not_found`
        $exceptions->render(fn (NotFoundException $e) => $error($e, 404));

        $exceptions->render(fn (InvalidArgumentException $e) => $error($e, 422));

        $exceptions->render(fn (ConflictException $e) => $error($e, 409));

        // Still reported to the log (with the command line for CommandFailedException)
        $exceptions->render(fn (SystemException $e) => $error($e, 500));

        // The same shape for what the framework refuses itself. A request that fails its field
        // rules also lists every message per field.
        $exceptions->render(fn (ValidationException $e) => $error($e, $e->status, $e->validator->errors()->first(), ['errors' => $e->errors()]));

        // No such route is `route_not_found`: never a link or a peer that isn't there
        $exceptions->render(fn (NotFoundHttpException $e) => $error($e, 404, $e->getMessage() ?: 'Resource not found.'));

        $exceptions->render(fn (HttpExceptionInterface $e) => $error($e, $e->getStatusCode(), $e->getMessage() ?: 'Request refused.', headers: $e->getHeaders()));

        // Anything else is a failure nothing above names (a bug): the same shape, and its details
        // only in the log. (A response an exception carries itself is the framework's to send.)
        $exceptions->render(fn (Throwable $e) => $e instanceof HttpResponseException ? null : response()->json(
            ['error' => config('app.debug') ? $e::class.': '.$e->getMessage() : 'Internal server error.', 'code' => ErrorCode::SYSTEM_ERROR], 500,
        ));
    })->create();
