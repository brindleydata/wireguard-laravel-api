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
    Route::patch('/link/{name}', [WireGuard::class, 'linkUpdate']);
    Route::delete('/link/{name}', [WireGuard::class, 'linkDelete']);

    // Peer routes
    Route::get('/link/{link}/peers', [WireGuard::class, 'peers']);
    Route::post('/link/{link}/peers', [WireGuard::class, 'peerCreate']);
    Route::patch('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerUpdate'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::delete('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerDelete'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::get('/link/{link}/peer/{pubkey}/config', [WireGuard::class, 'peerConfig'])->where('pubkey', '[A-Za-z0-9_-]+');
});
