<?php

namespace App\Services;

use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

class Shell
{
    protected const PATH = '/opt/homebrew/bin:/opt/homebrew/sbin:/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin';

    /**
     * Run a shell command and return trimmed output. Throws on failure.
     *
     * Supports named parameter binding: placeholders like :name in the command
     * are replaced with escapeshellarg($bindings['name']).
     */
    public function run(string $command, array $bindings = [], ?string $input = null, ?float $timeout = 60): string
    {
        $command = $this->bind($command, $bindings);

        $process = Process::fromShellCommandline($command);
        $process->setTimeout($timeout);
        $process->setEnv(['PATH' => self::PATH]);

        if ($input !== null) {
            $process->setInput($input);
        }

        $process->run();

        if (! $process->isSuccessful()) {
            throw new ProcessFailedException($process);
        }

        return trim($process->getOutput());
    }

    /**
     * Run a shell command, returning null on failure instead of throwing.
     */
    public function tryRun(string $command, array $bindings = [], ?string $input = null, ?float $timeout = 60): ?string
    {
        try {
            return $this->run($command, $bindings, $input, $timeout);
        } catch (\Throwable) {
            return null;
        }
    }

    protected function bind(string $command, array $bindings): string
    {
        // Sort by key length descending so :name_long isn't partially matched by :name
        uksort($bindings, fn ($a, $b) => strlen($b) - strlen($a));

        foreach ($bindings as $key => $value) {
            $command = str_replace(':'.$key, escapeshellarg($value), $command);
        }

        return $command;
    }
}
