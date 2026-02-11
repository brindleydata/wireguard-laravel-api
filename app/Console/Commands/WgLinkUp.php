<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkUp extends WgCommand
{
    protected $signature = 'wg:link:up {link}';

    protected $description = 'Bring up a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $wg->linkUp($name);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Link {$name} is up.");

        return Command::SUCCESS;
    }
}
