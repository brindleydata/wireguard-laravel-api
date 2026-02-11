<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkDelete extends WgCommand
{
    protected $signature = 'wg:link:delete {link : Interface name}';

    protected $description = 'Delete a WireGuard link';

    public function handle(WireGuard $wg): int
    {
        $name = $this->argument('link');

        try {
            $wg->deleteLink($name);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info("Deleted link {$name}");

        return Command::SUCCESS;
    }
}
