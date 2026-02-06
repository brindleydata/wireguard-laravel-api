<?php

use App\Http\Controllers\WireGuard;
use App\Http\Middleware\AuthenticateByApiKey;
use Illuminate\Support\Facades\Route;

Route::get('/status', [WireGuard::class, 'status']);

Route::middleware(AuthenticateByApiKey::class)->group(function () {
    // Interface routes
    Route::get('/interfaces', [WireGuard::class, 'interfaces']);
    Route::get('/interface/{name}', [WireGuard::class, 'interface']);
    Route::post('/interface', [WireGuard::class, 'interfaceAdd']);
    Route::delete('/interface/{name}', [WireGuard::class, 'interfaceDelete']);

    // Peer routes
    Route::get('/interface/{interface}/peers', [WireGuard::class, 'peers']);
    Route::post('/interface/{interface}/peers', [WireGuard::class, 'peerAdd']);
    Route::delete('/interface/{interface}/peer/{peer}', [WireGuard::class, 'peerDelete']);
    Route::get('/interface/{interface}/peer/{ip}/config', [WireGuard::class, 'peerConfig']);
});
