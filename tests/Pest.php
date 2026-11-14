<?php

use Symfony\Component\Process\Process;
use Tests\TestCase;

/*
 * Feature tests boot the Laravel app; unit tests run as plain test cases.
 */
pest()->extend(TestCase::class)->in('Feature');

/*
 * Each service scenario runs against a simulated host of both OSes (see Tests\Fakes\FakeHost).
 */
dataset('os', ['linux' => 'linux', 'macOS' => 'mac']);

dataset('firewall states', [
    'forward' => [true, false],
    'nat' => [false, true],
    'forward + nat' => [true, true],
]);

/*
 * A pf ruleset the real pfctl accepts (parse only: no root needed). Skipped where pfctl is missing.
 */
expect()->extend('toBeAcceptedByPf', function () {
    if (! is_executable('/sbin/pfctl')) {
        return $this;
    }

    $process = new Process(['/sbin/pfctl', '-n', '-f', '-'], input: $this->value);
    $process->run();

    expect($process->getExitCode())->toBe(0, "pfctl rejected:\n{$this->value}\n".$process->getErrorOutput());

    return $this;
});
