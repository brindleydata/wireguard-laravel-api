<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

/**
 * Base class of the wg:* commands, and `wg:help` itself.
 */
class WgCommand extends Command
{
    protected $signature = 'wg:help';

    protected $description = 'How to set up and update this server';

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
