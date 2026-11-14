<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\RunsSetupSteps;
use App\Services\WireGuard;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Installer;
use App\Setup\Step;
use App\Setup\Steps\Server;
use Illuminate\Console\Command;

class WgInstall extends WgCommand
{
    use RunsSetupSteps;

    protected $signature = 'wg:install
        {--step=* : Only these steps: packages, web-user, permissions, environment, forwarding, pf, helper, sudoers, apparmor, server, health}
        {--print : Print the commands as a shell script instead of checking and running anything}
        {--yes : Fix everything without asking (needs passwordless sudo)}
        {--user= : User that runs the API}
        {--hostname= : Public hostname or IP that VPN clients connect to}
        {--forward= : Whether links route traffic for their peers (true/false)}
        {--tls= : letsencrypt, cert or http}
        {--port= : Port the API listens on}
        {--domain= : Domain for the Let\'s Encrypt certificate}
        {--cert= : Certificate file (with --tls=cert)}
        {--key= : Private key file (with --tls=cert)}
        {--bind= : Address to listen on (with --tls=http)}';

    protected $description = 'Set up this server step by step (re-run any time to check it)';

    /** Runs as the deploy user, who owns the code. */
    protected function runsAsWebUser(): bool
    {
        return false;
    }

    public function handle(WireGuard $wg): int
    {
        $installer = app(Installer::class);
        $print = (bool) $this->option('print');
        $yes = (bool) $this->option('yes');
        $interactive = ! $print && ! $yes && $this->input->isInteractive();

        $forward = $this->option('forward');
        $ctx = $installer->context([
            'web_user' => $this->option('user'),
            'hostname' => $this->option('hostname'),
            'forward' => $forward === null ? null : filter_var($forward, FILTER_VALIDATE_BOOLEAN),
            'tls' => $this->option('tls'),
            'port' => $this->option('port'),
            'domain' => $this->option('domain'),
            'cert' => $this->option('cert'),
            'key' => $this->option('key'),
            'bind' => $this->option('bind'),
        ]);

        $steps = $installer->steps();
        if ($only = $this->option('step')) {
            $unknown = array_diff($only, array_map(fn (Step $step) => $step->key(), $steps));
            if ($unknown !== []) {
                $this->error('Unknown step: '.implode(', ', $unknown));

                return Command::FAILURE;
            }
            $selected = array_values(array_filter($steps, fn (Step $step) => in_array($step->key(), $only, true)));
        }

        if (! $print) {
            if ($ctx->deployUser === 'root') {
                $this->error('Run this as the user that owns the app code, not as root; it uses sudo where needed.');

                return Command::FAILURE;
            }
            if (! $installer->sudoReady($interactive)) {
                $this->error($interactive ? 'This needs sudo.' : 'Without a terminal (or with --yes) this needs passwordless sudo.');

                return Command::FAILURE;
            }
        }

        if ($print) {
            $this->line("#!/bin/sh\n# php artisan wg:install --print, for {$ctx->app()}\nset -e");
        }

        $pending = [];
        foreach ($selected ?? $steps as $step) {
            if (! $step->applies($ctx)) {
                continue;
            }

            if (! $this->answer($step, $ctx, $interactive)) {
                return Command::FAILURE;
            }
            $step->after($ctx);
            $installer->save($ctx);

            if ($print) {
                $this->printStep($step, $ctx);
            } elseif (! $this->fix($installer, $step, $ctx, $interactive, $yes)) {
                $pending[] = $step->title();
            }
        }

        if ($print) {
            return Command::SUCCESS;
        }

        $this->newLine();
        if ($pending !== []) {
            $this->error('Not done yet: '.implode(', ', $pending));
            $this->line('Fix them and run php artisan wg:install again.');

            return Command::FAILURE;
        }

        $this->summary($ctx, $installer);

        return Command::SUCCESS;
    }

    protected function summary(Context $ctx, Installer $installer): void
    {
        $key = (new EnvFile($ctx->app('.env')))->get('API_KEY');

        $this->info('All set.');
        if ($ctx->isMac()) {
            $this->line('Start the API (development): php artisan octane:start --server=frankenphp --port=8000');
            $url = 'http://127.0.0.1:8000';
        } else {
            $url = app(Server::class)->publicUrl($ctx);
            $this->line("API:     {$url}");
        }
        $this->line("API key: {$key}");
        $this->line("Try:     curl -H 'api-key: {$key}' ".explode(' ', $url)[0].'/links');
    }
}
