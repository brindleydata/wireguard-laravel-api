<?php

use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

use App\Http\Middleware\AuthenticateByApiKey;
use App\Http\Controllers\WireGuard;

Route::get('/status', [ WireGuard::class, 'status' ]);

Route::middleware(AuthenticateByApiKey::class)->group(function () {
    Route::get('/links', [ WireGuard::class, 'links' ]);
    Route::get('/link/{name}', [ WireGuard::class, 'link' ]);
    Route::post('/link', [ WireGuard::class, 'link_add' ]);
    Route::delete('/link/{name}', [ WireGuard::class, 'link_rm' ]);

    //Route::get('/links/{link}/peers', [ WireGuard::class, 'clients_list' ]);
    //Route::post('/links/{link}/peers', [ WireGuard::class, 'client_add' ]);
    //Route::delete('/links/{link}/{peer}', [ WireGuard::class, 'client_kill' ]);
});
