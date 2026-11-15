<?php

use App\Http\Controllers\WireGuard;
use App\Http\Middleware\AuthenticateByApiKey;
use Illuminate\Support\Facades\Route;

// Public: only whether the API can do its job (for load balancers and monitoring)
Route::get('/health', [WireGuard::class, 'health']);

Route::middleware(AuthenticateByApiKey::class)->group(function () {
    Route::get('/status', [WireGuard::class, 'status']);
    Route::get('/ip', [WireGuard::class, 'ip']);
    Route::get('/interfaces', [WireGuard::class, 'interfaces']);

    // Link routes
    Route::get('/links', [WireGuard::class, 'links']);
    Route::get('/link/{name}', [WireGuard::class, 'link']);
    Route::post('/link', [WireGuard::class, 'linkCreate']);
    Route::patch('/link/{name}', [WireGuard::class, 'linkUpdate']);
    Route::delete('/link/{name}', [WireGuard::class, 'linkDelete']);
    Route::post('/link/{name}/repair', [WireGuard::class, 'linkRepair']);
    Route::post('/link/{name}/rekey', [WireGuard::class, 'linkRekey']);

    // Peer routes
    Route::get('/link/{link}/peers', [WireGuard::class, 'peers']);
    Route::post('/link/{link}/peers', [WireGuard::class, 'peerCreate']);
    Route::get('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peer'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::patch('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerUpdate'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::delete('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerDelete'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::post('/link/{link}/peer/{pubkey}/rekey', [WireGuard::class, 'peerRekey'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::get('/link/{link}/peer/{pubkey}/config', [WireGuard::class, 'peerConfig'])->where('pubkey', '[A-Za-z0-9_-]+');
    Route::get('/link/{link}/peer/{pubkey}/qr', [WireGuard::class, 'peerQr'])->where('pubkey', '[A-Za-z0-9_-]+');
});
