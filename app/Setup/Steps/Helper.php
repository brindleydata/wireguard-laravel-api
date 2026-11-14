<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

/**
 * The root helper must be exactly the bundled bin/wgla-helper, owned by root and writable by
 * nobody else: whoever can change it can run anything as root.
 */
class Helper extends Step
{
    public function key(): string
    {
        return 'helper';
    }

    public function title(): string
    {
        return 'Root helper';
    }

    public function check(Context $ctx): array
    {
        $path = $ctx->helperPath;
        if (! is_file($path)) {
            return ["The root helper is not installed at {$path}"];
        }

        $problems = [];
        if (hash_file('sha256', $path) !== hash_file('sha256', $ctx->bundledHelper)) {
            $problems[] = sprintf('%s differs from the bundled helper (installed v%s, app v%s)', $path, $this->version($path), $this->version($ctx->bundledHelper));
        }
        if (fileowner($path) !== 0 || (fileperms($path) & 0022) !== 0) {
            $problems[] = "{$path} must be owned by root and writable by nobody else";
        }
        if ($ctx->separateWebUser() && $this->webUserCan($ctx, '-w', dirname($path))) {
            $problems[] = $ctx->webUser().' can write '.dirname($path).' and could replace the helper';
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        $path = self::q($ctx->helperPath);

        // mkdir -p leaves an existing directory's owner alone (Homebrew owns /usr/local/sbin on Intel Macs)
        return [Action::command(
            'Install the bundled helper, owned by root',
            'sudo mkdir -p '.self::q(dirname($ctx->helperPath)).' && sudo install -o root -g '.$ctx->rootGroup()
            .' -m 755 '.self::q($ctx->bundledHelper)." {$path}",
        )];
    }

    /** It runs as root: show what changes before replacing an installed one. */
    public function notice(Context $ctx): ?string
    {
        if (! is_file($ctx->helperPath) || hash_file('sha256', $ctx->helperPath) === hash_file('sha256', $ctx->bundledHelper)) {
            return null;
        }

        $diff = (string) $this->shell->tryRun('diff -u :installed :bundled || true', ['installed' => $ctx->helperPath, 'bundled' => $ctx->bundledHelper]);

        return "Changes to the root helper (it runs as root):\n".implode("\n", array_slice(explode("\n", $diff), 0, 200));
    }

    protected function version(string $path): string
    {
        return preg_match('/^VERSION=(\S+)$/m', (string) @file_get_contents($path), $m) ? $m[1] : '?';
    }
}
