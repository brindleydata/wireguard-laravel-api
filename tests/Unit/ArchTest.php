<?php

/*
 * The CLI and HTTP frontends are thin: they go through the WireGuard and Server services and
 * never reach Shell, the OS drivers, the validator or other internals directly. An allowlist,
 * so a new internal class is covered without changing this test.
 */
arch('frontends only use the WireGuard, Server and Backup services')
    ->expect(['App\Http\Controllers', 'App\Console\Commands'])
    ->toOnlyUse([
        'App\Services\WireGuard',
        'App\Services\Server',
        'App\Services\Backup',
        'App\DTOs',
        'App\Console\Commands', // the WgCommand base class
        'App\Setup', // wg:install / wg:update: setting up the host is their job
        'Laravel\Prompts',
        'Symfony\Component\Console', // WgCommand::execute(): the wrong-user guard
        'Illuminate',
        'abort', 'app', 'response', 'config', 'base_path', 'storage_path', // Laravel helper functions
    ]);
