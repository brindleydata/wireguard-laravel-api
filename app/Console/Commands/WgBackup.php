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
            $this->warnAboutUnmanaged($backup->links($payload), fn (string $warning) => fwrite(STDERR, $warning."\n"));

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
        $this->warnAboutUnmanaged($backup->links($payload), fn (string $warning) => $this->warn($warning));
        $this->line('Keep the passphrase safe: without it the backup cannot be restored.');

        return Command::SUCCESS;
    }

    /**
     * A restore rebuilds every config, so it can't take a hand-written one with settings the app
     * doesn't write.
     *
     * @param  array<string, array{unmanaged: list<string>}>  $links
     * @param  callable(string): mixed  $warn  stdout may be the backup itself
     */
    protected function warnAboutUnmanaged(array $links, callable $warn): void
    {
        foreach ($links as $name => $link) {
            if ($link['unmanaged'] !== []) {
                $warn(sprintf(
                    "%s has settings this app doesn't manage (%s). It is in the backup, but a restore will skip it: keep a copy of its config file too.",
                    $name, implode(', ', $link['unmanaged']),
                ));
            }
        }
    }
}
