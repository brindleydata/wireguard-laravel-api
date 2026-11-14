<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgLinkRepair extends WgCommand
{
    protected $signature = 'wg:link:repair {link : Interface name}';

    protected $description = 'Put a running link\'s forward/NAT rules back in place';

    public function handle(WireGuard $wg): int
    {
        try {
            $link = $wg->repairLink($this->argument('link'));
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $this->info(match ($link->firewall) {
            'ok' => "The firewall rules of {$link->name} are in place.",
            'missing' => "The firewall rules of {$link->name} are still missing.",
            default => $link->up ? "{$link->name} has neither forward nor NAT: no rules to install." : "{$link->name} is down: its rules are installed when it starts.",
        });

        return $link->firewall === 'missing' ? Command::FAILURE : Command::SUCCESS;
    }
}
