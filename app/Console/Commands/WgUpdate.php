<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\RunsSetupSteps;
use App\Services\WireGuard;
use App\Setup\Context;
use App\Setup\Installer;
use App\Setup\Step;
use App\Setup\Steps\Server;
use App\Setup\Updater;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;

/**
 * Update the app to a release, in two stages:
 *
 * 1. With the running (old) code: record the update, check out the release and install its
 *    dependencies.
 * 2. In a new process with the new code (`--finish`): fetch the current FrankenPHP, bring the
 *    root helper, sudo rule, route policy and service up to date, reload the API (restart it
 *    when FrankenPHP changed) and wait until it runs the new code, check its health.
 *
 * If stage 2 fails, the previous version is checked out again, with the FrankenPHP from before,
 * and finished the same way (`--back`). An update that never ended is gone back from by the next.
 */
class WgUpdate extends WgCommand
{
    use RunsSetupSteps;

    /** Installer steps an update can affect. */
    private const STEPS = ['environment', 'helper', 'sudoers', 'policy', 'apparmor', 'firewall', 'shortcut', 'server', 'health'];

    protected $signature = 'wg:update
        {--to= : A release tag (or any git ref) to move to; default: the latest release}
        {--branch= : Follow the head of a branch instead of releases (for testing)}
        {--yes : Don\'t ask (needs passwordless sudo)}
        {--finish= : (internal) Finish an update that came from this commit}
        {--back : (internal) With --finish: the way back from a failed update, which fetches no FrankenPHP and restarts the API}';

    protected $description = 'Update the app to the latest release (or --to / --branch)';

    /** Runs as the deploy user, who owns the code. */
    protected function runsAsWebUser(): bool
    {
        return false;
    }

    /** The answers an update uses are the ones wg:install saved, and only it takes new ones. */
    protected function answerHint(string $option): string
    {
        return "(php artisan wg:install {$option} sets it)";
    }

    public function handle(WireGuard $wg): int
    {
        $installer = app(Installer::class);
        $updater = app(Updater::class);
        $yes = (bool) $this->option('yes');
        $interactive = ! $yes && $this->interactive();
        $ctx = $installer->context();

        if ($ctx->deployUser === 'root') {
            $this->error('Run this as the user that owns the app code, not as root; it uses sudo where needed.');

            return Command::FAILURE;
        }
        // wg:install saves who runs the API. Without that, the steps below would set this server
        // up for the deploy user: its sudo rule, .env and service, and the web user loses them.
        if ($ctx->answer('web_user') === null) {
            $this->error("WGLA_WEB_USER is not in .env, so it isn't known which user runs the API. Set this server up with php artisan wg:install first.");

            return Command::FAILURE;
        }

        if ($this->option('finish') !== null) {
            return $this->finish($installer, $updater, $ctx, $interactive, $yes) ? Command::SUCCESS : Command::FAILURE;
        }

        if (! $updater->isCheckout($ctx)) {
            $this->error("{$ctx->app()} is not a git checkout, so it can't be updated in place.");

            return Command::FAILURE;
        }
        if (($unfinished = $updater->unfinished($ctx)) !== null) {
            return $this->resume($installer, $updater, $ctx, $unfinished, $interactive, $yes);
        }
        if ($changes = $updater->localChanges($ctx)) {
            $this->error('There are local changes to the code; an update would overwrite them:');
            foreach ($changes as $change) {
                $this->line("  {$change}");
            }

            return Command::FAILURE;
        }
        if (! $updater->fetch($ctx)) {
            $this->error('Fetching from origin failed.');

            return Command::FAILURE;
        }

        $target = match (true) {
            $this->option('branch') !== null => 'origin/'.$this->option('branch'),
            $this->option('to') !== null => $this->option('to'),
            default => $updater->latestRelease($ctx),
        };
        if ($target === null) {
            $this->error('There are no releases (tags vX.Y.Z) yet. Use --branch= to follow a branch.');

            return Command::FAILURE;
        }

        $current = (string) $updater->commit($ctx, 'HEAD');
        $next = $updater->commit($ctx, $target);
        if ($next === null) {
            $this->error("{$target} doesn't exist.");

            return Command::FAILURE;
        }
        if ($next === $current) {
            $this->info("Already at {$updater->name($ctx, $current)}.");

            return Command::SUCCESS;
        }
        // Only asked for (--to) does an update go back: a checkout ahead of the latest release
        // (a clone of a branch) has nothing to update
        if ($this->option('to') === null && $this->option('branch') === null && ($ahead = $updater->ahead($ctx, $next, $current)) !== null) {
            $this->info('This checkout is '.($ahead === 1 ? '1 commit' : "{$ahead} commits")." ahead of the latest release, {$target}: there is nothing to update.");
            $this->line("--to={$target} goes back to that release, --branch= follows a branch.");

            return Command::SUCCESS;
        }
        // Decided before anything changes: git can't finish a checkout that has to write where
        // the deploy user can't (storage/ is the web user's), and going back would be as stuck
        if ($blocked = $updater->unwritable($ctx, $current, $next)) {
            $this->error("This update changes files where {$ctx->deployUser} can't write, so git would leave it half done:");
            foreach (array_keys($blocked) as $path) {
                $this->line("  {$path}");
            }
            $this->line("Nothing changed. Let {$ctx->deployUser} write there for the update, then run php artisan wg:install, which gives storage/ back to {$ctx->webUser()}:");
            $this->line("  sudo chown {$ctx->deployUser} ".implode(' ', array_map('escapeshellarg', array_unique($blocked))));

            return Command::FAILURE;
        }

        $this->line("Update <options=bold>{$updater->name($ctx, $current)}</> → <options=bold>{$updater->name($ctx, $next)}</>");
        $this->newLine();
        $this->line($updater->changelog($ctx, $current, $next) ?: '(going back: no new commits)');
        if (($diff = $updater->helperDiff($ctx, $current, $next)) !== '') {
            $this->newLine();
            $this->warn('The root helper changes (it runs as root, review it):');
            $this->line($diff);
        }
        $this->newLine();

        if (! $yes && (! $interactive || ! confirm('Update now?', default: false))) {
            $this->line('Nothing changed.');

            return Command::FAILURE;
        }
        if (! $installer->sudoReady($interactive)) {
            $this->error($interactive ? 'This needs sudo.' : 'With --yes this needs passwordless sudo.');

            return Command::FAILURE;
        }

        $update = $updater->begin($ctx, $current, $next);
        if ($update === null) {
            $this->error("The update can't be recorded in git's directory (as {$ctx->deployUser}), so an interrupted one couldn't be told from one that is done. Nothing changed.");

            return Command::FAILURE;
        }

        if ($this->move($updater, $ctx, $next) && $updater->finish($ctx, $current, $yes)) {
            if (! $updater->end($ctx)) {
                $this->error("Updated, but {$updater->recordPath($ctx)} can't be removed: the next update would take this one for unfinished and go back first. Remove it.");

                return Command::FAILURE;
            }
            $this->info("Updated to {$updater->name($ctx, $next)}.");

            return Command::SUCCESS;
        }

        $this->error("The update failed. Going back to {$updater->name($ctx, $current)}.");
        if ($this->goBack($updater, $ctx, $update, $yes)) {
            $this->warn("Back at {$updater->name($ctx, $current)}.");
        } else {
            $this->error("Going back failed too. Check the output above, then run php artisan wg:update again: it goes back to {$updater->name($ctx, $current)} first.");
        }

        return Command::FAILURE;
    }

    /**
     * An update that never ended (Ctrl-C, a dropped SSH session) may have left the code between
     * two versions, without the new one's setup. Go back to where it started, then update anew in
     * a new process: this one may run the code the update was on its way to.
     *
     * @param  array{from: ?string, to: ?string, frankenphp: ?string}  $update
     */
    protected function resume(Installer $installer, Updater $updater, Context $ctx, array $update, bool $interactive, bool $yes): int
    {
        if ($update['from'] === null || $update['to'] === null) {
            $this->error("{$updater->recordPath($ctx)} says an update didn't end, but not which one. Check out the version this server should run, run php artisan wg:install, then remove that file.");

            return Command::FAILURE;
        }

        $from = $updater->name($ctx, $update['from']);
        $this->warn("An update from {$from} to {$updater->name($ctx, $update['to'])} didn't end. Going back to {$from} first.");
        if (! $installer->sudoReady($interactive)) {
            $this->error($interactive ? 'This needs sudo.' : 'With --yes this needs passwordless sudo.');

            return Command::FAILURE;
        }
        if (! $this->goBack($updater, $ctx, $update, $yes)) {
            $this->error('Going back failed. Check the output above, then run php artisan wg:update again.');

            return Command::FAILURE;
        }
        $this->info("Back at {$from}.");
        $this->newLine();

        return $updater->update($ctx, ['to' => $this->option('to'), 'branch' => $this->option('branch'), 'yes' => $yes])
            ? Command::SUCCESS : Command::FAILURE;
    }

    /**
     * The way back from an update that failed or never ended: the FrankenPHP binary it replaced
     * goes back in place, the commit it came from is checked out (whatever it left half done goes)
     * and finished with `--back`, and only then is the update over: until then, the next one
     * starts by going back.
     *
     * @param  array{from: string, to: string, frankenphp: ?string}  $update
     */
    protected function goBack(Updater $updater, Context $ctx, array $update, bool $yes): bool
    {
        $restored = $updater->restoreFrankenPhp($ctx, $update['frankenphp']);
        if ($restored) {
            $this->line('<info>✓</info> FrankenPHP is the one from before the update again');
        } elseif ($restored === null) {
            $this->warn('  The FrankenPHP from before the update is gone: the one it brought stays.');
        }

        return $this->move($updater, $ctx, $update['from'], back: true)
            && $updater->finish($ctx, $update['to'], $yes, back: true)
            && $updater->end($ctx);
    }

    /**
     * Check out a commit and install its dependencies. Going back ($back) discards whatever the
     * failed update left half done.
     */
    protected function move(Updater $updater, Context $ctx, string $commit, bool $back = false): bool
    {
        $this->line("→ Checking out {$updater->name($ctx, $commit)}");
        if (! $updater->checkout($ctx, $commit, force: $back)) {
            if ($changes = $updater->localChanges($ctx)) {
                $this->error('  The checkout is incomplete:');
                foreach ($changes as $change) {
                    $this->line("    {$change}");
                }
            }

            return false;
        }

        $this->line('→ Installing dependencies');

        return $updater->composerInstall($ctx);
    }

    /**
     * Stage 2, running the new code: helper, sudo rule, policy, service, reload, health. On the
     * way back (`--back`), with the FrankenPHP that was there before: none is fetched, and the API
     * is restarted, as it may still run the one the failed update brought (a reload keeps that).
     */
    protected function finish(Installer $installer, Updater $updater, Context $ctx, bool $interactive, bool $yes): bool
    {
        if (! $installer->sudoReady($interactive)) {
            $this->error('This needs sudo.');

            return false;
        }

        $steps = array_filter($installer->steps(), fn (Step $step) => in_array($step->key(), self::STEPS, true) && $step->applies($ctx));
        $back = (bool) $this->option('back');

        // The web server is not part of the release: every update brings its current version
        $server = array_find($steps, fn (Step $step) => $step instanceof Server);
        $new_server = false;
        if ($server !== null && ! $back && is_file($ctx->app('frankenphp'))) {
            $installed = $server->frankenPhpVersion($ctx);
            if ($installed !== null && $installed === $server->latestFrankenPhp()) {
                $this->line("<info>✓</info> FrankenPHP {$installed} is the current release");
            } else {
                $this->line('→ Fetching the current FrankenPHP');
                $new_server = $updater->refreshFrankenPhp($ctx, $server->downloadFrankenPhp($ctx));
                if ($new_server === null) {
                    $this->warn('  That failed. The installed FrankenPHP stays; the next update tries again.');
                }
            }
        }

        foreach ($steps as $step) {
            // After the service step (its unit may have changed too), before the health check
            if ($server !== null && ($new_server || $back) && $step->key() === 'health') {
                $this->line($back ? '→ Restarting the API with the FrankenPHP from before' : '→ Restarting the API with the new FrankenPHP');
                if (! $updater->restartApi()) {
                    return false;
                }
            }

            if (! $this->answer($step, $ctx, $interactive)) {
                return false;
            }
            $step->after($ctx);
            $installer->save($ctx);
            // (The server step reloads the API: it still runs the old code.)

            if (! $this->fix($installer, $step, $ctx, $interactive, $yes)) {
                return false;
            }

            // The links that run keep the rules the helper before wrote, which firewall-check now
            // reads as missing where the new one writes others: the repair puts them as it writes
            // them, now rather than within a minute (the timer would)
            if ($step->key() === 'firewall') {
                $this->line('→ Firewall rules of running links as this version writes them');
                if (! $updater->repairFirewall()) {
                    $this->warn('  That failed. The repair timer tries again every minute.');
                }
            }
        }

        return true;
    }
}
