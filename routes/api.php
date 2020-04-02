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

Route::get('/status', 'WireGuardController@getStatus');

Route::middleware(AuthenticateByApiKey::class)->group(function () {
    Route::get('/interfaces', 'WireGuardController@getInterfaces');
    Route::post('/interfaces', 'WireGuardController@storeInterface');
    Route::get('/interfaces/{interface}', 'WireGuardController@getInterface');
    Route::delete('/interfaces/{interface}', 'WireGuardController@destroyInterface');

    Route::get('/clients/{interface}', 'WireGuardController@getClients');
    Route::post('/clients/{interface}', 'WireGuardController@storeClient');
    Route::delete('/clients/{interface}/{client}', 'WireGuardController@destroyClient');
});
