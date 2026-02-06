<?php

namespace App\Services;

use Symfony\Component\Process\Exception\ProcessFailedException;
use Symfony\Component\Process\Process;

class Shell
{
    /**
     * Run a shell command and return trimmed output. Throws on failure.
     */
    public function run(string $command, ?string $input = null, ?float $timeout = 60): string
    {
        $process = Process::fromShellCommandline($command);
        $process->setTimeout($timeout);

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
     * Run a command using array form (no shell interpolation). Throws on failure.
     */
    public function exec(array $command, ?string $input = null, ?float $timeout = 60): string
    {
        $process = new Process($command);
        $process->setTimeout($timeout);

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
    public function tryRun(string $command, ?string $input = null, ?float $timeout = 60): ?string
    {
        try {
            return $this->run($command, $input, $timeout);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * Run an array-form command, returning null on failure instead of throwing.
     */
    public function tryExec(array $command, ?string $input = null, ?float $timeout = 60): ?string
    {
        try {
            return $this->exec($command, $input, $timeout);
        } catch (\Throwable) {
            return null;
        }
    }
}
