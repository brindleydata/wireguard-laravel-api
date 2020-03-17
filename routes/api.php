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

Route::middleware('auth:api')->get('/user', function (Request $request) {
    return $request->user();
});

Route::get('/', 'Controller@index');
Route::get('/link/{link}', 'Controller@getInterface');
Route::post('/link/{link}', 'Controller@storeInterface');
Route::delete('/link/{link}', 'Controller@destroyInterface');
Route::get('/{link}/{client}', 'Controller@getClient');
Route::post('/{link}/{client}', 'Controller@storeClient');
Route::delete('/{link}/{client}', 'Controller@destroyClient');
