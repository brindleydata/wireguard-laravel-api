<?php

namespace App\Console\Commands;

use App\Services\Server;
use App\Services\WireGuard;
use Illuminate\Console\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Base class of the wg:* commands, and `wg:help` itself.
 */
class WgCommand extends Command
{
    protected $signature = 'wg:help';

    protected $description = 'How to set up and update this server';

    /**
     * Link and peer commands run as the web user, like the API: same sudo rule, same lock files.
     * As anyone else they'd fail with an unhelpful "sudo: a password is required".
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $web = config('wireguard.web_user');
        $user = app(Server::class)->processUser();

        if ($this->runsAsWebUser() && $web && $user !== $web) {
            $this->error("Run this as {$web}, the user the API runs as:");
            $this->line("  sudo -u {$web} php artisan {$this->getName()} ...");

            return self::FAILURE;
        }

        return parent::execute($input, $output);
    }

    protected function runsAsWebUser(): bool
    {
        return $this->getName() !== 'wg:help';
    }

    public function handle(WireGuard $wg): int
    {
        $this->line(<<<'HELP'
            Set up this server (run as the user that owns the code, not root):

              php artisan wg:install          step by step; re-run it any time to check the setup
              php artisan wg:install --print  the same commands as a shell script, to review or run yourself
              php artisan wg:install --yes    unattended, with answers as options (see --help)

            Update to the latest release:

              php artisan wg:update           shows the changes (and any root helper diff) first

            Everything else runs as the web server user, e.g.:

              sudo -u www-data php artisan wg:links
            HELP);

        return Command::SUCCESS;
    }
}
