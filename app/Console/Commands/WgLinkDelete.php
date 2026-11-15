<?php

namespace App\Console\Commands;

use App\Services\WireGuard;

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
            return $this->failed($e->getMessage());
        }

        return $this->respond(['message' => "Deleted link: {$name}"], fn () => $this->info("Deleted link {$name}"));
    }
}
