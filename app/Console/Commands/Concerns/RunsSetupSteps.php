<?php

namespace App\Console\Commands\Concerns;

use App\Setup\Context;
use App\Setup\Installer;
use App\Setup\Question;
use App\Setup\Step;

use function Laravel\Prompts\confirm;
use function Laravel\Prompts\select;
use function Laravel\Prompts\text;

/**
 * The terminal side of installer steps, shared by wg:install and wg:update: ask a step's
 * questions, check it, show and run its fix.
 */
trait RunsSetupSteps
{
    /** Fill in a step's answers: ask in a terminal, else take options, saved answers and defaults. */
    protected function answer(Step $step, Context $ctx, bool $interactive): bool
    {
        foreach ($step->questions($ctx) as $question) {
            if (! $question->applies($ctx)) {
                continue;
            }

            $value = $ctx->answers[$question->key] ?? $question->defaultFor($ctx);
            do {
                if ($interactive) {
                    $value = $this->prompt($question, $ctx, $value);
                } elseif ($value === null || ($error = $question->error($value, $ctx)) !== null) {
                    $this->error(($error ?? "{$question->label}: no answer").' (pass --'.str_replace('web_', '', $question->key).'=…)');

                    return false;
                }

                $warning = $question->warningFor($value, $ctx);
                if ($warning !== null) {
                    $this->warn($warning);
                }
            } while ($warning !== null && $interactive && ! confirm('Keep this?', default: false));

            $ctx->answers[$question->key] = $value;
        }

        return true;
    }

    protected function prompt(Question $question, Context $ctx, mixed $default): mixed
    {
        $validate = fn ($value) => $question->error($value, $ctx);

        return match ($question->type) {
            'confirm' => confirm($question->label, default: filter_var($default ?? true, FILTER_VALIDATE_BOOLEAN), hint: $question->hint),
            'select' => select($question->label, $question->options, default: array_key_exists((string) $default, $question->options) ? (string) $default : null, hint: $question->hint),
            default => text($question->label, default: (string) ($default ?? ''), required: true, validate: $validate, hint: $question->hint),
        };
    }

    /** Check a step and, if it isn't done, offer its fix. Returns whether the step ends up done. */
    protected function fix(Installer $installer, Step $step, Context $ctx, bool $interactive, bool $yes): bool
    {
        $problems = $step->check($ctx);
        if ($problems === []) {
            $this->line("<info>✓</info> {$step->title()}");

            return true;
        }

        $this->newLine();
        $this->line("<fg=red>✗</> <options=bold>{$step->title()}</>");
        foreach ($problems as $problem) {
            $this->line("    {$problem}");
        }

        $plan = $step->plan($ctx);
        if ($plan === []) {
            $this->warn('    '.$step->manual($ctx));

            return false;
        }

        if ($notice = $step->notice($ctx)) {
            $this->newLine();
            $this->line($notice);
        }

        $this->newLine();
        foreach ($plan as $action) {
            $this->line("    <comment>{$action->description}</comment>");
            $this->line('      '.($action->command === null ? '(done by the installer)' : '$ '.$action->command));
        }

        $choice = match (true) {
            $yes => 'run',
            $interactive => select('Fix it?', ['run' => 'Run these now', 'manual' => "I'll run them myself", 'skip' => 'Skip for now']),
            default => 'manual',
        };
        if ($choice !== 'run') {
            return false;
        }

        foreach ($plan as $action) {
            $this->line("  → {$action->description}");
            if (! $installer->run($action, $ctx)) {
                $this->error('    That failed.');

                return false;
            }
        }

        $remaining = $step->check($ctx);
        if ($remaining === []) {
            $this->line("<info>✓</info> {$step->title()}");

            return true;
        }

        foreach ($remaining as $problem) {
            $this->error("    Still: {$problem}");
        }
        if ($manual = $step->manual($ctx)) {
            $this->warn("    {$manual}");
        }

        return false;
    }

    protected function printStep(Step $step, Context $ctx): void
    {
        $plan = $step->plan($ctx);
        if ($plan === []) {
            return;
        }

        $this->line("\n# {$step->title()}");
        foreach ($plan as $action) {
            $this->line("# {$action->description}");
            $this->line($action->command ?? "php artisan wg:install --step={$step->key()} --yes");
        }
    }
}
