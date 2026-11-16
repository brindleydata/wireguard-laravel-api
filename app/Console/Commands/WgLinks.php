<?php

namespace App\Console\Commands;

use App\Exceptions\ErrorCode;
use App\Services\WireGuard;

class WgLinks extends WgCommand
{
    protected $signature = 'wg:links';

    protected $description = 'List WireGuard links';

    public function handle(WireGuard $wg): int
    {
        try {
            $links = $wg->listLinks();
        } catch (\Throwable $e) {
            return $this->failed('Could not retrieve WireGuard links: '.$e->getMessage(), ErrorCode::of($e));
        }

        return $this->respond($links, function () use ($links) {
            if ($links === []) {
                $this->warn('No WireGuard links found.');

                return;
            }

            $this->info('Available WireGuard links:');
            $this->line(implode(' ', $links));
        });
    }
}
