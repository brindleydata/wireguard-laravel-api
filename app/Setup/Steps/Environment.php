<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Question;
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

    public function questions(Context $ctx): array
    {
        return [new Question(
            key: 'hostname',
            label: 'Public hostname or IP that VPN clients connect to',
            default: fn (Context $ctx) => $this->env($ctx)->get('WIREGUARD_HOSTNAME') ?: $this->detectHostname(),
            validate: fn ($value) => preg_match('/^[A-Za-z0-9.:-]+$/', (string) $value) ? null : 'Not a hostname or IP address.',
            hint: 'Goes into every client config as the Endpoint.',
        )];
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
        if ($env->get('WIREGUARD_HOSTNAME') !== (string) $ctx->answer('hostname')) {
            $problems[] = 'WIREGUARD_HOSTNAME is not '.$ctx->answer('hostname');
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
            Action::php('Create .env and fill in keys and hostname', function (Context $ctx) {
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
                $env->set('WIREGUARD_HOSTNAME', (string) $ctx->answer('hostname'));
                $env->set('OCTANE_SERVER', 'frankenphp');
            }),
            $ctx->separateWebUser()
                ? Action::command("Let {$ctx->webUser()} read .env, nobody else", 'sudo chgrp '.self::q($ctx->webGroup())." {$path} && chmod 640 {$path}")
                : Action::command('Make .env private', "chmod 600 {$path}"),
        ];
    }

    public function env(Context $ctx): EnvFile
    {
        return new EnvFile($ctx->app('.env'));
    }

    protected function detectHostname(): string
    {
        $hostname = (string) gethostname();
        if (str_contains($hostname, '.')) {
            return $hostname;
        }

        $ip = $this->shell->tryRun('curl -4 -s --max-time 5 :url', ['url' => config('wireguard.ip_service', 'http://ifconfig.me/ip')]);

        return $ip && filter_var($ip, FILTER_VALIDATE_IP) ? $ip : $hostname;
    }
}
