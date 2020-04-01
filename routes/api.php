<?php

use Illuminate\Http\Request;
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

Route::get('/interfaces', 'WireGuardController@getInterfaces');
Route::post('/interfaces', 'WireGuardController@storeInterface');
Route::get('/interfaces/{interface}', 'WireGuardController@getInterface');
Route::delete('/interfaces/{interface}', 'WireGuardController@destroyInterface');
Route::get('/status', 'WireGuardController@getStatus');

Route::post('/interfaces/{interface}/client', 'WireGuardController@storeClient');
Route::delete('/interfaces/{interface}/client/{client}', 'WireGuardController@destroyClient');
