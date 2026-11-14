<?php

namespace App\Console\Commands\Concerns;

use function Laravel\Prompts\password;

/**
 * The backup passphrase: from --passphrase-file, else WGLA_BACKUP_PASSPHRASE, else asked.
 */
trait AsksForPassphrase
{
    protected function passphrase(bool $confirm): ?string
    {
        if ($file = $this->option('passphrase-file')) {
            $content = @file_get_contents($file);
            if ($content === false) {
                $this->error("Can't read {$file}.");

                return null;
            }

            return rtrim(strtok($content, "\n") ?: '', "\r");
        }

        if (($env = getenv('WGLA_BACKUP_PASSPHRASE')) !== false && $env !== '') {
            return $env;
        }

        if (! $this->input->isInteractive()) {
            $this->error('No passphrase: pass --passphrase-file= or set WGLA_BACKUP_PASSPHRASE.');

            return null;
        }

        $passphrase = password('Backup passphrase', required: true);
        if ($confirm && password('Again, to be sure', required: true) !== $passphrase) {
            $this->error("The passphrases don't match.");

            return null;
        }

        return $passphrase;
    }
}
