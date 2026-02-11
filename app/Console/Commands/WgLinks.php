<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinks extends WgCommand
{
    protected $signature = 'wg:links';

    protected $description = 'List WireGuard links';

    public function handle(WireGuard $wg): int
    {
        try {
            $links = $wg->listLinks();
        } catch (\Throwable $e) {
            $this->error('Could not retrieve WireGuard links: '.$e->getMessage());

            return Command::FAILURE;
        }

        if (empty($links)) {
            $this->warn('No WireGuard links found.');

            return Command::SUCCESS;
        }

        $this->info('Available WireGuard links:');
        $this->line(implode(' ', $links));

        return Command::SUCCESS;
    }
}
