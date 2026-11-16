<?php

use App\Http\Controllers\WireGuard;
use App\Http\Middleware\AuthenticateByApiKey;
use Illuminate\Support\Facades\Route;

// Public: only whether the API can do its job, and that it is this app (for load balancers,
// monitoring, and a client that checks the URL before it sends its API key)
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
    Route::post('/link/{name}/adopt', [WireGuard::class, 'linkAdopt']);

    // Peer routes. {pubkey} is taken as it comes: a malformed one is a peer that isn't there to a
    // read (404 peer_not_found) and invalid input to a change (422), never "no such route"
    Route::get('/link/{link}/peers', [WireGuard::class, 'peers']);
    Route::post('/link/{link}/peers', [WireGuard::class, 'peerCreate']);
    Route::get('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peer']);
    Route::patch('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerUpdate']);
    Route::delete('/link/{link}/peer/{pubkey}', [WireGuard::class, 'peerDelete']);
    Route::post('/link/{link}/peer/{pubkey}/rekey', [WireGuard::class, 'peerRekey']);
    Route::get('/link/{link}/peer/{pubkey}/config', [WireGuard::class, 'peerConfig']);
    Route::get('/link/{link}/peer/{pubkey}/qr', [WireGuard::class, 'peerQr']);
});
