<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkDown extends WgCommand
{
    protected $signature = 'wg:link:down {link}';

    protected $description = 'Bring down a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $wg->linkDown($name);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Link {$name} is down.");

        return Command::SUCCESS;
    }
}
