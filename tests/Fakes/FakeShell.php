<?php

namespace Tests\Fakes;

use App\Services\Shell;
use LogicException;

/**
 * Shell double. Commands are matched by their template (e.g. `sudo cat :path`), so handlers get
 * the raw binding values. An unknown command fails the test unless a fallback is set; handlers
 * signal a non-zero exit by throwing CommandFailed (which tryRun() turns into null).
 */
class FakeShell extends Shell
{
    /** @var list<array{command: string, bindings: array, input: ?string, bound: string}> */
    public array $calls = [];

    /** @var array<string, callable(array, ?string): ?string> */
    protected array $handlers = [];

    /** @var (callable(string, array, ?string): ?string)|null */
    protected $fallback = null;

    public function on(string $command, callable $handler): static
    {
        $this->handlers[$command] = $handler;

        return $this;
    }

    /**
     * Handle every command without a dedicated handler.
     */
    public function otherwise(callable $handler): static
    {
        $this->fallback = $handler;

        return $this;
    }

    public function run(string $command, array $bindings = [], ?string $input = null, ?float $timeout = 60): string
    {
        $bound = $this->bind($command, $bindings);
        $this->calls[] = compact('command', 'bindings', 'input', 'bound');

        if (isset($this->handlers[$command])) {
            return trim((string) ($this->handlers[$command])($bindings, $input));
        }

        if ($this->fallback !== null) {
            return trim((string) ($this->fallback)($command, $bindings, $input));
        }

        throw new LogicException("Unexpected shell command: {$bound}");
    }

    public function tryRun(string $command, array $bindings = [], ?string $input = null, ?float $timeout = 60): ?string
    {
        try {
            return $this->run($command, $bindings, $input, $timeout);
        } catch (CommandFailed) {
            return null;
        }
    }

    /** @var list<string> commands run through interactive() */
    public array $interactive = [];

    /** @var (callable(string): int)|null */
    protected $interactiveHandler = null;

    /** Decide the exit code of interactive() commands (default: 0). */
    public function onInteractive(callable $handler): static
    {
        $this->interactiveHandler = $handler;

        return $this;
    }

    public function interactive(string $command): int
    {
        $this->interactive[] = $command;

        return $this->interactiveHandler === null ? 0 : ($this->interactiveHandler)($command);
    }

    /**
     * @return list<array{command: string, bindings: array, input: ?string, bound: string}>
     */
    public function callsTo(string $command): array
    {
        return array_values(array_filter($this->calls, fn (array $call) => $call['command'] === $command));
    }
}
