<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\RunsSetupSteps;
use App\Services\WireGuard;
use App\Setup\Context;
use App\Setup\Installer;
use App\Setup\Step;
use App\Setup\Updater;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;

/**
 * Update the app to a release, in two stages:
 *
 * 1. With the running (old) code: check out the release and install its dependencies.
 * 2. In a new process with the new code (`--finish`): bring the root helper, sudo rule and
 *    service up to date, reload the API, check its health.
 *
 * If stage 2 fails, the previous version is checked out again and finished the same way.
 */
class WgUpdate extends WgCommand
{
    use RunsSetupSteps;

    /** Installer steps an update can affect. */
    private const STEPS = ['environment', 'helper', 'sudoers', 'server', 'health'];

    protected $signature = 'wg:update
        {--to= : A release tag (or any git ref) to move to; default: the latest release}
        {--branch= : Follow the head of a branch instead of releases (for testing)}
        {--yes : Don\'t ask (needs passwordless sudo)}
        {--finish= : (internal) Finish an update that came from this commit}';

    protected $description = 'Update the app to the latest release (or --to / --branch)';

    /** Runs as the deploy user, who owns the code. */
    protected function runsAsWebUser(): bool
    {
        return false;
    }

    public function handle(WireGuard $wg): int
    {
        $installer = app(Installer::class);
        $updater = app(Updater::class);
        $yes = (bool) $this->option('yes');
        $interactive = ! $yes && $this->input->isInteractive();
        $ctx = $installer->context();

        if ($ctx->deployUser === 'root') {
            $this->error('Run this as the user that owns the app code, not as root; it uses sudo where needed.');

            return Command::FAILURE;
        }

        if ($this->option('finish') !== null) {
            return $this->finish($installer, $ctx, $interactive, $yes) ? Command::SUCCESS : Command::FAILURE;
        }

        if (! $updater->isCheckout($ctx)) {
            $this->error("{$ctx->app()} is not a git checkout, so it can't be updated in place.");

            return Command::FAILURE;
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

        if ($this->move($updater, $ctx, $next) && $updater->finish($ctx, $current, $yes)) {
            $this->info("Updated to {$updater->name($ctx, $next)}.");

            return Command::SUCCESS;
        }

        $this->error("The update failed. Going back to {$updater->name($ctx, $current)}.");
        if ($this->move($updater, $ctx, $current) && $updater->finish($ctx, $next, $yes)) {
            $this->warn("Back at {$updater->name($ctx, $current)}.");
        } else {
            $this->error('Going back failed too. Check the output above, then run php artisan wg:install.');
        }

        return Command::FAILURE;
    }

    /** Check out a commit and install its dependencies. */
    protected function move(Updater $updater, Context $ctx, string $commit): bool
    {
        $this->line("→ Checking out {$updater->name($ctx, $commit)}");
        if (! $updater->checkout($ctx, $commit)) {
            return false;
        }

        $this->line('→ Installing dependencies');

        return $updater->composerInstall($ctx);
    }

    /** Stage 2, running the new code: helper, sudo rule, service, reload, health. */
    protected function finish(Installer $installer, Context $ctx, bool $interactive, bool $yes): bool
    {
        if (! $installer->sudoReady($interactive)) {
            $this->error('This needs sudo.');

            return false;
        }

        $steps = array_filter($installer->steps(), fn (Step $step) => in_array($step->key(), self::STEPS, true) && $step->applies($ctx));
        foreach ($steps as $step) {
            if (! $this->answer($step, $ctx, $interactive)) {
                return false;
            }
            $installer->save($ctx);
            // (The server step reloads the API: it still runs the old code.)

            if (! $this->fix($installer, $step, $ctx, $interactive, $yes)) {
                return false;
            }
        }

        return true;
    }
}
