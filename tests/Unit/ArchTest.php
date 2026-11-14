<?php

/*
 * The CLI and HTTP frontends are thin: they go through the WireGuard and Server services and
 * never reach Shell, the OS drivers, the validator or other internals directly. An allowlist,
 * so a new internal class is covered without changing this test.
 */
arch('frontends only use the WireGuard and Server services')
    ->expect(['App\Http\Controllers', 'App\Console\Commands'])
    ->toOnlyUse([
        'App\Services\WireGuard',
        'App\Services\Server',
        'App\DTOs',
        'App\Console\Commands', // the WgCommand base class
        'App\Setup', // wg:install / wg:update: setting up the host is their job
        'Laravel\Prompts',
        'Illuminate',
        'abort', 'app', 'response', 'config', 'base_path', // Laravel helper functions
    ]);
