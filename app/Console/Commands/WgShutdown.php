<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgShutdown extends WgCommand
{
    protected $signature = 'wg:shutdown';

    protected $description = 'Gracefully tear down all WireGuard interfaces (configs are preserved)';

    public function handle(WireGuard $wg): int
    {
        $results = $wg->shutdownAll();

        if ($results === []) {
            $this->info('No active interfaces to shut down.');

            return Command::SUCCESS;
        }

        $failed = 0;

        foreach ($results as $name => $success) {
            if ($success) {
                $this->line("  {$name}: stopped");
            } else {
                $this->error("  {$name}: failed");
                $failed++;
            }
        }

        if ($failed > 0) {
            $this->error("{$failed} interface(s) failed to stop.");

            return Command::FAILURE;
        }

        $this->info('All interfaces stopped. Configs preserved for next startup.');

        return Command::SUCCESS;
    }
}
