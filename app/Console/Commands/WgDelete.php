<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgDelete extends WgCommand
{
    protected $signature = 'wg:delete {interface}';

    protected $description = 'Delete a WireGuard interface';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('interface');

        try {
            $wg->deleteInterface($name);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Deleted interface {$name}");

        return Command::SUCCESS;
    }
}
