<?php

use App\Exceptions\NotFoundException;
use App\Http\Middleware\ForceJsonResponse;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;

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
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (NotFoundHttpException $e) {
            return response()->json(['error' => $e->getMessage() ?: 'Resource not found.'], 404);
        });

        $exceptions->render(function (NotFoundException $e) {
            return response()->json(['error' => $e->getMessage()], 404);
        });

        $exceptions->render(function (\InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        });
    })->create();
