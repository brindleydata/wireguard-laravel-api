<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Step;

class Environment extends Step
{
    public function key(): string
    {
        return 'environment';
    }

    public function title(): string
    {
        return 'Configuration (.env)';
    }

    public function check(Context $ctx): array
    {
        $env = $this->env($ctx);
        if (! $env->exists()) {
            return ['There is no .env file'];
        }

        $problems = [];
        if (! $env->get('APP_KEY')) {
            $problems[] = 'APP_KEY is not set';
        }
        if (! $env->get('API_KEY')) {
            $problems[] = 'API_KEY is not set (the API refuses every protected request without it)';
        }
        if (($version = $this->version($ctx)) !== null && $env->get('APP_VERSION') !== $version) {
            $problems[] = "APP_VERSION is not {$version} (the checked-out release)";
        }
        if ($env->get('OCTANE_SERVER') !== 'frankenphp') {
            $problems[] = 'OCTANE_SERVER is not frankenphp';
        }

        // Secrets: readable by the web user's group at most
        $mode = fileperms($env->path) & 0777;
        $group = function_exists('posix_getgrgid') ? (posix_getgrgid(filegroup($env->path))['name'] ?? '') : '';
        if ($ctx->separateWebUser() ? ($mode !== 0640 || $group !== $ctx->webGroup()) : $mode !== 0600) {
            $problems[] = sprintf('.env permissions are %o, not %s', $mode, $ctx->separateWebUser() ? "640 with group {$ctx->webGroup()}" : '600');
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        $path = self::q($this->env($ctx)->path);

        return [
            // An update only has a new APP_VERSION to write: it shouldn't read as a new .env
            Action::php($this->env($ctx)->exists() ? 'Bring .env up to date' : 'Create .env and fill in its keys', function (Context $ctx) {
                $env = $this->env($ctx);
                if (! $env->exists()) {
                    copy($ctx->app('.env.example'), $env->path);
                    chmod($env->path, 0600);
                }
                if (! $env->get('APP_KEY')) {
                    $env->set('APP_KEY', 'base64:'.base64_encode(random_bytes(32)));
                }
                if (! $env->get('API_KEY')) {
                    $env->set('API_KEY', bin2hex(random_bytes(32)));
                }
                $env->set('OCTANE_SERVER', 'frankenphp');
                if (($version = $this->version($ctx)) !== null) {
                    $env->set('APP_VERSION', $version);
                }
            }),
            $ctx->separateWebUser()
                ? Action::command("Let {$ctx->webUser()} read .env, nobody else", 'sudo chgrp '.self::q($ctx->webGroup())." {$path} && chmod 640 {$path}")
                : Action::command('Make .env private', "chmod 600 {$path}"),
        ];
    }

    /** The checked-out release (tag, or tag-N-gHASH, -dirty with local changes); null outside a git checkout. */
    public function version(Context $ctx): ?string
    {
        return $this->shell->tryRun('git -C :app describe --tags --always --dirty', ['app' => $ctx->app()]) ?: null;
    }

    public function env(Context $ctx): EnvFile
    {
        return new EnvFile($ctx->app('.env'));
    }
}
