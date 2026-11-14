<?php

namespace Tests\Support;

use Symfony\Component\Process\Process;

/**
 * Runs shell snippets the way wg-quick runs hooks (bash, `set -e -o pipefail`, eval), with the
 * named commands replaced by stubs that record their argv and stdin. `sudo` simply runs its
 * arguments, so commands the app builds for Shell can be replayed too.
 */
final class Bash
{
    /**
     * Returns the exit status and stderr, `calls` (the argv of each stub call, command name
     * first) and `stdin` (what each `... -f -` call read).
     *
     * @param  array<string, int>  $stubs  command name => exit status
     * @return array{exit: int, stderr: string, calls: list<list<string>>, stdin: list<string>}
     */
    public static function run(string $script, array $stubs): array
    {
        $dir = sys_get_temp_dir().'/wgla_bash_'.bin2hex(random_bytes(6));
        mkdir($dir);

        $prelude = ['set -e -o pipefail', 'sudo() { "$@"; }', 'n=0'];
        foreach ($stubs as $name => $status) {
            // \037 (unit separator) between arguments keeps argument boundaries visible
            $prelude[] = $name.'() { { printf %s '.$name.'; printf "\037%s" "$@"; printf "\n"; } >> "$WG_LOG";'
                .' if [ "${@: -1}" = "-" ]; then n=$((n+1)); cat > "$WG_DIR/stdin.$n"; fi; return '.$status.'; }';
        }

        $process = new Process(
            ['bash', '-c', implode("\n", $prelude)."\n".'eval "$WG_SCRIPT"'],
            env: ['WG_LOG' => "{$dir}/log", 'WG_DIR' => $dir, 'WG_SCRIPT' => $script],
        );
        $process->run();

        $calls = [];
        foreach (file_exists("{$dir}/log") ? file("{$dir}/log", FILE_IGNORE_NEW_LINES) : [] as $line) {
            $calls[] = explode("\037", $line);
        }

        $stdin = [];
        for ($i = 1; file_exists("{$dir}/stdin.{$i}"); $i++) {
            $stdin[] = file_get_contents("{$dir}/stdin.{$i}");
        }

        array_map('unlink', glob("{$dir}/*"));
        rmdir($dir);

        return ['exit' => $process->getExitCode(), 'stderr' => $process->getErrorOutput(), 'calls' => $calls, 'stdin' => $stdin];
    }

    /**
     * Expand hook placeholders like wg-quick: on macOS %i is the real utunN and %I the config
     * name; on Linux both are the interface name.
     */
    public static function expand(string $hook, string $iface, ?string $link = null): string
    {
        return str_replace(['%i', '%I'], [$iface, $link ?? $iface], $hook);
    }

    /**
     * Value of a `Key = value` line in a wg-quick config.
     */
    public static function confValue(string $conf, string $key): ?string
    {
        return preg_match('/^'.preg_quote($key, '/').' = (.*)$/m', $conf, $m) ? $m[1] : null;
    }
}
