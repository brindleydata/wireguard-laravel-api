<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\RunsSetupSteps;
use App\Services\WireGuard;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Installer;
use App\Setup\Step;
use App\Setup\Steps\Server;
use App\Setup\Updater;
use Illuminate\Console\Command;

class WgInstall extends WgCommand
{
    use RunsSetupSteps;

    protected $signature = 'wg:install
        {--step=* : Only these steps: packages, web-user, permissions, environment, forwarding, pf, helper, sudoers, policy, apparmor, firewall, shortcut, server, health}
        {--print : Print the commands as a shell script instead of checking and running anything}
        {--yes : Fix everything without asking (needs passwordless sudo)}
        {--user= : User that runs the API}
        {--forward= : Whether links route traffic for their peers (true/false)}
        {--allow-default-route= : Whether peers may route a default route, 0.0.0.0/0 or ::/0 (true/false; default false)}
        {--allow-own-networks= : Whether peers may route networks with this server\'s own addresses or gateway (true/false; default false)}
        {--tls= : letsencrypt, cert or http}
        {--port= : Port the API listens on}
        {--domain= : Domain for the Let\'s Encrypt certificate}
        {--cert= : Certificate file (with --tls=cert)}
        {--key= : Private key file (with --tls=cert)}
        {--bind= : Address to listen on (with --tls=http)}
        {--admin-port= : Local port of FrankenPHP\'s admin API (default: 2019, or the next free one)}';

    protected $description = 'Set up this server step by step (re-run any time to check it)';

    /** The answers options give: answer => option. */
    public const OPTIONS = [
        'web_user' => 'user',
        'forward' => 'forward',
        'allow_default_route' => 'allow-default-route',
        'allow_own_networks' => 'allow-own-networks',
        'tls' => 'tls',
        'port' => 'port',
        'domain' => 'domain',
        'cert' => 'cert',
        'key' => 'key',
        'bind' => 'bind',
        'admin_port' => 'admin-port',
    ];

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
        $interactive = ! $print && ! $yes && $this->interactive();

        try {
            $flags = array_map(fn (string $option) => $this->flag($option), [
                'forward' => 'forward',
                'allow_default_route' => 'allow-default-route',
                'allow_own_networks' => 'allow-own-networks',
            ]);
            $admin_port = $this->number('admin-port');
            if ($admin_port !== null && ($admin_port < 1 || $admin_port > 65535)) {
                throw new \InvalidArgumentException('--admin-port must be a port number.');
            }
        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }
        $ctx = $installer->context([
            ...array_map(fn (string $option) => $this->option($option), self::OPTIONS),
            ...$flags,
            'admin_port' => $admin_port === null ? null : (string) $admin_port,
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

        // A script printed as root would make root the code's owner (and the shortcut's deploy user)
        if ($ctx->deployUser === 'root') {
            $this->error('Run this as the user that owns the app code, not as root; it uses sudo where needed.');

            return Command::FAILURE;
        }

        if ($print) {
            return $this->printScript($selected ?? $steps, $ctx) ? Command::SUCCESS : Command::FAILURE;
        }

        // The code may be between two versions, without the new one's setup: set up from that,
        // this server would run neither. wg:update goes back first, then updates anew.
        $updater = app(Updater::class);
        if (($update = $updater->unfinished($ctx)) !== null) {
            $this->error(($update['from'] !== null && $update['to'] !== null
                ? "An update from {$updater->name($ctx, $update['from'])} to {$updater->name($ctx, $update['to'])} didn't end"
                : "{$updater->recordPath($ctx)} says an update didn't end").'. Run php artisan wg:update first: it goes back to where that one started.');

            return Command::FAILURE;
        }

        if (! $installer->sudoReady($interactive)) {
            $this->error($interactive ? 'This needs sudo.' : 'Without a terminal (or with --yes) this needs passwordless sudo.');

            return Command::FAILURE;
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
            if (! $this->fix($installer, $step, $ctx, $interactive, $yes)) {
                $pending[] = $step->title();
            }
            // Once more: the environment step may just have created .env
            $installer->save($ctx);
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

    /**
     * --print: the steps' commands as a shell script, nothing checked, run or saved. Every
     * question is answered first, so the script's one PHP step (editing .env) gets every answer
     * and saves it there, as a run here would: wg:update reads them back.
     *
     * @param  list<Step>  $steps
     */
    protected function printScript(array $steps, Context $ctx): bool
    {
        $planned = [];
        foreach ($steps as $step) {
            if (! $step->applies($ctx)) {
                continue;
            }
            if (! $this->answer($step, $ctx, false)) {
                return false;
            }
            $step->after($ctx);
            $planned[] = $step;
        }

        $this->line("#!/bin/sh\n# php artisan wg:install --print, for {$ctx->app()}\nset -e");
        foreach ($planned as $step) {
            $this->printStep($step, $ctx);
        }

        return true;
    }

    protected function printStep(Step $step, Context $ctx): void
    {
        $plan = $step->plan($ctx);
        if ($plan === []) {
            return;
        }

        $options = '';
        foreach (self::OPTIONS as $answer => $option) {
            if (($value = $ctx->answer($answer)) !== null) {
                $options .= " --{$option}=".escapeshellarg(is_bool($value) ? ($value ? 'true' : 'false') : (string) $value);
            }
        }

        $this->line("\n# {$step->title()}");
        foreach ($plan as $action) {
            $this->line("# {$action->description}");
            $this->line($action->command ?? escapeshellarg($ctx->php).' '.escapeshellarg($ctx->app('artisan'))." wg:install --step={$step->key()} --yes{$options}");
        }
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
