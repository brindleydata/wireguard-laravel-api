<?php

namespace Tests\Support;

use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use RuntimeException;
use Symfony\Component\Process\Process;

/**
 * Runs the real root helper (bin/wgla-helper) unprivileged, against temp config/run directories
 * and stub system commands that record their argv and stdin.
 *
 * As root the helper ignores these overrides and would act on the real system, so this refuses
 * to run as root.
 */
final class HelperSandbox
{
    private const STUBS = ['wg', 'wg-quick', 'nft', 'iptables', 'ip6tables', 'systemctl', 'pfctl'];

    public readonly string $dir;

    public readonly string $confDir;

    public readonly string $runDir;

    /** @var list<string> */
    private static array $dirs = [];

    /**
     * @param  string  $os  Linux or Darwin
     */
    public function __construct(public readonly string $os = 'Linux')
    {
        if (self::isRoot()) {
            throw new RuntimeException('Refusing to run the root helper tests as root');
        }

        $this->dir = sys_get_temp_dir().'/wgla_helper_'.bin2hex(random_bytes(6));
        $this->confDir = "{$this->dir}/conf";
        $this->runDir = "{$this->dir}/run";
        foreach (['conf', 'run', 'stubs', 'out', 'rc'] as $sub) {
            mkdir("{$this->dir}/{$sub}", 0700, true);
        }
        self::$dirs[] = $this->dir;

        foreach (self::STUBS as $stub) {
            $this->addStub($stub);
        }
        // Like a host where nothing in ip6tables drops forwarded traffic (tests change it as needed)
        $this->respond('ip6tables -S FORWARD', '-P FORWARD ACCEPT');
    }

    public static function isRoot(): bool
    {
        return (function_exists('posix_geteuid') ? posix_geteuid() : (int) trim((string) shell_exec('id -u'))) === 0;
    }

    /** The helper as installed in the repo (also what the app's hooks must name in tests). */
    public static function path(): string
    {
        return realpath(__DIR__.'/../../bin/wgla-helper');
    }

    /**
     * @return array{exit: int, stdout: string, stderr: string}
     */
    public function run(array $args, ?string $input = null): array
    {
        // Stdin comes from a file, not a pipe: the helper may stop reading early (size limit)
        file_put_contents("{$this->dir}/input", (string) $input);

        $process = new Process(['/bin/sh', '-c', 'exec "$0" "$@" < "$WGLA_INPUT"', self::path(), ...$args], env: [
            'WGLA_OS' => $this->os,
            'WGLA_CONF_DIR' => $this->confDir,
            'WGLA_RUN_DIR' => $this->runDir,
            'WGLA_SANDBOX' => $this->dir,
            'WGLA_INPUT' => "{$this->dir}/input",
            // Stubs first; no sbin dirs, so a real iptables/nft is never picked up
            'PATH' => "{$this->dir}/stubs:/usr/bin:/bin",
        ]);
        $process->run();

        return ['exit' => $process->getExitCode(), 'stdout' => $process->getOutput(), 'stderr' => $process->getErrorOutput()];
    }

    /**
     * Make a stubbed command print $output and exit with $exit, for an exact command line.
     */
    public function respond(string $command, string $output = '', int $exit = 0): void
    {
        $key = str_replace('/', '_', $command);
        file_put_contents("{$this->dir}/out/{$key}", $output === '' ? '' : $output."\n");
        file_put_contents("{$this->dir}/rc/{$key}", (string) $exit);
    }

    /** Make every call of a stubbed command exit with $exit. */
    public function failing(string $name, int $exit = 1): void
    {
        file_put_contents("{$this->dir}/rc/{$name}", (string) $exit);
    }

    /** Take a command off the PATH, as if it weren't installed. */
    public function uninstall(string $name): void
    {
        unlink("{$this->dir}/stubs/{$name}");
    }

    /** @return list<list<string>> argv of every stub call, command name first */
    public function calls(): array
    {
        $log = "{$this->dir}/calls";

        return file_exists($log) ? array_map(fn ($line) => explode("\037", $line), file($log, FILE_IGNORE_NEW_LINES)) : [];
    }

    /** @return list<string> what each stub call read on stdin (`-f -` or /dev/stdin) */
    public function stdin(): array
    {
        $inputs = [];
        for ($i = 1; file_exists("{$this->dir}/stdin.{$i}"); $i++) {
            $inputs[] = file_get_contents("{$this->dir}/stdin.{$i}");
        }

        return $inputs;
    }

    public function writeConf(string $name, string $content): void
    {
        file_put_contents("{$this->confDir}/{$name}.conf", $content);
    }

    public static function cleanup(): void
    {
        foreach (self::$dirs as $dir) {
            if (! is_dir($dir)) {
                continue;
            }
            $entries = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST,
            );
            foreach ($entries as $entry) {
                $entry->isDir() && ! $entry->isLink() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
            }
            rmdir($dir);
        }
        self::$dirs = [];
    }

    private function addStub(string $name): void
    {
        $stub = <<<'BASH'
            #!/bin/bash
            # Records its argv and stdin, then prints/exits as configured by HelperSandbox::respond()
            name=${0##*/}
            { printf '%s' "$name"; printf '\037%s' "$@"; printf '\n'; } >> "$WGLA_SANDBOX/calls"
            for arg in "$@"; do
                if [ "$arg" = - ] || [ "$arg" = /dev/stdin ]; then
                    n=$(ls "$WGLA_SANDBOX" | grep -c '^stdin\.' || true)
                    cat > "$WGLA_SANDBOX/stdin.$((n + 1))"
                fi
            done
            key=$(printf '%s' "$name $*" | tr '/' '_')
            if [ -f "$WGLA_SANDBOX/out/$key" ]; then cat "$WGLA_SANDBOX/out/$key"; fi
            if [ -f "$WGLA_SANDBOX/rc/$key" ]; then exit "$(cat "$WGLA_SANDBOX/rc/$key")"; fi
            if [ -f "$WGLA_SANDBOX/rc/$name" ]; then exit "$(cat "$WGLA_SANDBOX/rc/$name")"; fi
            exit 0
            BASH;

        file_put_contents("{$this->dir}/stubs/{$name}", $stub."\n");
        chmod("{$this->dir}/stubs/{$name}", 0755);
    }
}
