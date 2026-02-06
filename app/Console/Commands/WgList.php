<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgList extends WgCommand
{
    protected $signature = 'wg:list';

    protected $description = 'List available WireGuard interfaces';

    public function handle(WireGuard $wg): int
    {
        try {
            $interfaces = $wg->listInterfaces();
        } catch (\Throwable $e) {
            $this->error('Could not retrieve WireGuard interfaces: '.$e->getMessage());

            return Command::FAILURE;
        }

        if (empty($interfaces)) {
            $this->warn('No WireGuard interfaces found.');

            return Command::SUCCESS;
        }

        $this->info('Available WireGuard interfaces:');
        $this->line(implode(' ', $interfaces));

        return Command::SUCCESS;
    }
}
