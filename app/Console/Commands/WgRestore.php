<?php

namespace App\Console\Commands;

use App\Console\Commands\Concerns\AsksForPassphrase;
use App\Services\Backup;
use App\Services\WireGuard;
use Illuminate\Console\Command;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\select;

class WgRestore extends WgCommand
{
    use AsksForPassphrase;

    protected $signature = 'wg:restore
        {file : The backup file; - for stdin}
        {--passphrase-file= : Read the passphrase from this file (else WGLA_BACKUP_PASSPHRASE, else asked)}
        {--existing= : For links that already exist here: skip or replace (asked when interactive)}
        {--yes : Restore without asking for confirmation}';

    protected $description = 'Restore links from a backup';

    public function handle(WireGuard $wg): int
    {
        $backup = app(Backup::class);
        $interactive = $this->input->isInteractive();
        $existing = $this->option('existing');
        if ($existing !== null && ! in_array($existing, ['skip', 'replace'], true)) {
            $this->error('--existing must be skip or replace.');

            return Command::FAILURE;
        }

        $file = $this->argument('file');
        $document = $file === '-' ? stream_get_contents(STDIN) : @file_get_contents($file);
        if ($document === false) {
            $this->error("Can't read {$file}.");

            return Command::FAILURE;
        }

        $passphrase = $this->passphrase(confirm: false);
        if ($passphrase === null) {
            return Command::FAILURE;
        }

        try {
            $payload = $backup->decrypt($document, $passphrase);
        } catch (\InvalidArgumentException $e) {
            $this->error($e->getMessage());

            return Command::FAILURE;
        }

        $links = $backup->links($payload);
        $this->line(sprintf('Backup of %s, made %s (version %s): %d link(s)',
            $payload['hostname'] ?? 'unknown host', $payload['created_at'] ?? '?', $payload['app_version'] ?? '?', count($links)));

        // Links that exist here: skip or replace, as the admin says
        $here = $wg->listLinks();
        $choices = [];
        foreach (array_keys($links) as $name) {
            if (! in_array($name, $here, true)) {
                $choices[$name] = 'restore';
            } elseif ($existing !== null) {
                $choices[$name] = $existing;
            } elseif ($interactive) {
                $choices[$name] = select("{$name} already exists here", ['skip' => 'Skip it (keep the one here)', 'replace' => 'Replace it with the one from the backup']);
            } else {
                $this->error("{$name} already exists here: pass --existing=skip or --existing=replace. Nothing was restored.");

                return Command::FAILURE;
            }
        }

        // Links that would clash with what stays here (port, subnet) can only be skipped
        $replaced = array_keys(array_filter($choices, fn (string $choice) => $choice === 'replace'));
        foreach ($choices as $name => $choice) {
            if ($choice === 'skip' || ($clashes = $backup->clashes($payload, $name, $replaced)) === []) {
                continue;
            }

            $why = implode('; ', $clashes);
            if ($existing === 'skip' || ($interactive && confirm("{$name} can't be restored here ({$why}). Skip it?", default: true))) {
                $choices[$name] = 'skip';
            } else {
                $this->error("{$name} can't be restored here: {$why}. Nothing was restored.");

                return Command::FAILURE;
            }
        }

        $this->table(['Link', 'Action', 'Address', 'Port', 'Peers', 'Was up'], array_map(fn (string $name) => [
            $name, $choices[$name], $links[$name]['address'], $links[$name]['port'], $links[$name]['peers'], $links[$name]['up'] ? 'yes' : 'no',
        ], array_keys($links)));

        if (! in_array('restore', $choices, true) && ! in_array('replace', $choices, true)) {
            $this->info('Nothing to restore.');

            return Command::SUCCESS;
        }
        if (! $this->option('yes') && (! $interactive || ! confirm('Restore now?', default: false))) {
            $this->line($interactive ? 'Nothing changed.' : 'Nothing changed: pass --yes to restore without a terminal.');

            return Command::FAILURE;
        }

        try {
            $report = $backup->restore($payload, $choices);
        } catch (\Throwable $e) {
            $this->error('Restore stopped: '.$e->getMessage());

            return Command::FAILURE;
        }

        $this->info(sprintf('Restored %s (%d client config(s)).', implode(', ', $report['restored']) ?: 'nothing', $report['clients']));
        if ($report['skipped'] !== []) {
            $this->line('Skipped: '.implode(', ', $report['skipped']));
        }
        foreach ($report['ifout'] as $name => [$from, $to]) {
            $this->warn("{$name}: outbound interface ".($from ?? '(none)')." doesn't exist here, using {$to}.");
        }
        if ($report['hostname_changed']) {
            $this->warn('Client configs now point at '.($report['hostname'] ?? 'this server').': peers need their new config (wg:peer, or GET /link/{link}/peer/{pubkey}/config).');
        }

        return Command::SUCCESS;
    }
}
