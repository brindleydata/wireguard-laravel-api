<?php

namespace App\Setup;

use App\Services\Shell;

/**
 * One installer step: ask what it needs, check whether it's done, and plan the fix. Steps never
 * change anything themselves; the installer runs their actions. Checks must be safe to repeat,
 * so re-running the wizard doubles as a health check.
 */
abstract class Step
{
    public function __construct(protected Shell $shell) {}

    /** Name for `wg:install --step=` */
    abstract public function key(): string;

    abstract public function title(): string;

    public function applies(Context $ctx): bool
    {
        return true;
    }

    /** @return list<Question> */
    public function questions(Context $ctx): array
    {
        return [];
    }

    /** Derive more answers once the questions are answered. */
    public function after(Context $ctx): void {}

    /** @return list<string> what's wrong; empty when the step is done */
    abstract public function check(Context $ctx): array;

    /** @return list<Action> what fixes it; empty when it can only be fixed by hand */
    abstract public function plan(Context $ctx): array;

    /**
     * check() again, right after the fix ran. A step whose fix takes effect a moment later (a
     * service that starts) waits for it here, not in check(), which would make every run wait.
     *
     * @return list<string>
     */
    public function recheck(Context $ctx): array
    {
        return $this->check($ctx);
    }

    /** Instructions shown when plan() is empty. */
    public function manual(Context $ctx): string
    {
        return '';
    }

    /** Extra information shown before the fix is offered (e.g. a diff). */
    public function notice(Context $ctx): ?string
    {
        return null;
    }

    protected function has(string $binary): bool
    {
        return $this->shell->tryRun('command -v :bin', ['bin' => $binary]) !== null;
    }

    /** Run a check command as root (the installer caches sudo credentials first). */
    protected function asRoot(string $command, array $bindings = []): ?string
    {
        return $this->shell->tryRun("sudo -n {$command}", $bindings);
    }

    /** Whether the web user can do `test $flag path` (e.g. -w, -r). */
    protected function webUserCan(Context $ctx, string $flag, string $path): bool
    {
        return $this->asRoot("-u :user test {$flag} :path", ['user' => $ctx->webUser(), 'path' => $path]) !== null;
    }

    protected static function q(string $value): string
    {
        return escapeshellarg($value);
    }
}
