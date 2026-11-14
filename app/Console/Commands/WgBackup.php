<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\AsksForPassphrase;
use App\Services\Backup;
use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgBackup extends WgCommand
{
    use AsksForPassphrase;

    protected $signature = 'wg:backup
        {file? : Where to write it; - for stdout (default: storage/app/backups/wgla-<time>.backup)}
        {--passphrase-file= : Read the passphrase from this file (else WGLA_BACKUP_PASSPHRASE, else asked)}';

    protected $description = 'Back up every link, its keys and client configs (encrypted with a passphrase)';

    public function handle(WireGuard $wg): int
    {
        $backup = app(Backup::class);
        $file = $this->argument('file') ?? storage_path('app/backups/wgla-'.gmdate('Ymd-His').'.backup');

        if ($file !== '-' && file_exists($file)) {
            $this->error("{$file} already exists.");

            return Command::FAILURE;
        }

        $passphrase = $this->passphrase(confirm: true);
        if ($passphrase === null) {
            return Command::FAILURE;
        }

        try {
            $payload = $backup->create();
            $document = $backup->encrypt($payload, $passphrase);
        } catch (\Throwable $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        if ($file === '-') {
            fwrite(STDOUT, $document);

            return Command::SUCCESS;
        }

        // Private from the start: it holds every private key (encrypted, but still)
        if (! is_dir(dirname($file))) {
            mkdir(dirname($file), 0700, true);
        }
        $umask = umask(0077);
        $written = file_put_contents($file, $document);
        umask($umask);
        if ($written === false) {
            $this->error("Can't write {$file}.");

            return Command::FAILURE;
        }

        $clients = array_sum(array_map(fn (array $link) => count($link['clients']), $payload['links']));
        $this->info(sprintf('Backed up %d link(s) and %d client config(s) to %s', count($payload['links']), $clients, $file));
        $this->line('Keep the passphrase safe: without it the backup cannot be restored.');

        return Command::SUCCESS;
    }
}
