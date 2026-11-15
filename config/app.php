<?php

return [

    'name' => env('APP_NAME', 'WireGuard API'),
    // Set by wg:install / wg:update from the checked-out release (git describe)
    'version' => env('APP_VERSION', 'dev'),
    'env' => env('APP_ENV', 'production'),
    'debug' => env('APP_DEBUG', false),
    'url' => env('APP_URL', 'http://localhost'),
    'timezone' => 'UTC',
    'locale' => 'en',
    'fallback_locale' => 'en',
    'key' => env('APP_KEY'),
    'cipher' => 'AES-256-CBC',

];
