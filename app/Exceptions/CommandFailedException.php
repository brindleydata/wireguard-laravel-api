<?php

namespace App\Exceptions;

use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

/**
 * A shell command exited non-zero. The message carries the exit status and stderr; the command
 * line goes only to the log (via context()), since it is not meant for API clients.
 */
class CommandFailedException extends SystemException
{
    public function __construct(
        string $message = 'Command failed',
        public readonly string $command = '',
        public readonly ?int $exitCode = null,
        public readonly string $output = '',
    ) {
        parent::__construct($message);
    }

    public static function fromProcess(Process $process): self
    {
        $output = trim($process->getErrorOutput()) ?: trim($process->getOutput());
        $message = "Command failed with exit code {$process->getExitCode()}";

        return new self(
            $output === '' ? $message : $message.': '.Str::limit($output, 500),
            $process->getCommandLine(),
            $process->getExitCode(),
            $output,
        );
    }

    public function context(): array
    {
        return ['command' => $this->command, 'exit_code' => $this->exitCode, 'output' => $this->output];
    }
}
