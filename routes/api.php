<?php

use App\Http\Controllers\WireGuard;
use App\Http\Middleware\AuthenticateByApiKey;
use Illuminate\Support\Facades\Route;

Route::get('/status', [WireGuard::class, 'status']);
Route::get('/ip', [WireGuard::class, 'ip']);

Route::middleware(AuthenticateByApiKey::class)->group(function () {
    // Link routes
    Route::get('/links', [WireGuard::class, 'links']);
    Route::get('/link/{name}', [WireGuard::class, 'link']);
    Route::post('/link', [WireGuard::class, 'linkCreate']);
    Route::delete('/link/{name}', [WireGuard::class, 'linkDelete']);
    Route::post('/link/{name}/up', [WireGuard::class, 'linkUp']);
    Route::post('/link/{name}/down', [WireGuard::class, 'linkDown']);

    // Peer routes
    Route::get('/link/{link}/peers', [WireGuard::class, 'peers']);
    Route::post('/link/{link}/peers', [WireGuard::class, 'peerCreate']);
    Route::delete('/link/{link}/peer/{ip}', [WireGuard::class, 'peerDelete']);
    Route::get('/link/{link}/peer/{ip}/config', [WireGuard::class, 'peerConfig']);
});
