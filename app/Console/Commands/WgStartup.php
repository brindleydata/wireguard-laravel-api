<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgStartup extends WgCommand
{
    protected $signature = 'wg:startup';

    protected $description = 'Restore all persisted WireGuard interfaces';

    public function handle(WireGuard $wg): int
    {
        $configured = $wg->configuredInterfaces();

        if ($configured === []) {
            $this->info('No persisted interfaces to restore.');

            return Command::SUCCESS;
        }

        $this->info('Restoring '.count($configured).' interface(s)...');

        $results = $wg->startupAll();
        $failed = 0;

        foreach ($results as $name => $success) {
            if ($success) {
                $this->line("  {$name}: restored");
            } else {
                $this->error("  {$name}: failed");
                $failed++;
            }
        }

        if ($failed > 0) {
            $this->error("{$failed} interface(s) failed to restore.");

            return Command::FAILURE;
        }

        $this->info('All interfaces restored.');

        return Command::SUCCESS;
    }
}
