<?php

namespace App\Services;

use App\Exceptions\CommandFailedException;
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

        $process = $this->process($command);
        $process->setTimeout($timeout);

        if ($input !== null) {
            $process->setInput($input);
        }

        $process->run();

        if (! $process->isSuccessful()) {
            throw CommandFailedException::fromProcess($process);
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

    /**
     * Run a command attached to the terminal (so sudo can ask for a password and output streams
     * live), returning its exit code. For the installer, never for request handling.
     */
    public function interactive(string $command): int
    {
        $process = $this->process($command);
        $process->setTimeout(null);

        if (Process::isTtySupported()) {
            $process->setTty(true);

            return $process->run();
        }

        return $process->run(function (string $type, string $output) {
            fwrite($type === Process::ERR ? STDERR : STDOUT, $output);
        });
    }

    /**
     * Always from /: commands use absolute paths, and the caller's directory may be one the
     * process user can't enter (e.g. `sudo -u www-data php /srv/wgla/artisan …` run from a home
     * directory), which makes every command fail.
     */
    protected function process(string $command): Process
    {
        $process = Process::fromShellCommandline($command, '/');
        $process->setEnv(['PATH' => self::PATH]);

        return $process;
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
