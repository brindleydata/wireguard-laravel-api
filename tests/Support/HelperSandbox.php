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

    /** Lookups of the host's own addresses (route policy): answered, but not in calls() */
    private const QUIET_STUBS = ['ip', 'ifconfig', 'route'];

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
        foreach (self::QUIET_STUBS as $stub) {
            $this->addStub($stub, quiet: true);
        }
        // Like a host where nothing in ip6tables drops forwarded traffic (tests change it as needed)
        $this->respond('ip6tables -S FORWARD', '-P FORWARD ACCEPT');
        // The host's own addresses and gateway, as FakeHost has them
        $this->respond('ip -o address show', "1: lo    inet 127.0.0.1/8 scope host lo\n2: eth0    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n2: eth0    inet6 2001:db8:f::10/64 scope global\n2: eth0    inet6 fe80::1/64 scope link");
        $this->respond('ip route show default', 'default via 192.0.2.1 dev eth0 proto dhcp');
        $this->respond('ifconfig -a', "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\nen0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n\tinet 192.0.2.10 netmask 0xffffff00 broadcast 192.0.2.255\n\tinet6 2001:db8:f::10 prefixlen 64 autoconf secured");
        $this->respond('route -n get default', "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.0.2.1\n  interface: en0");
    }

    /** The server's route policy (wg:install writes it as root; WGLA_POLICY points here) */
    public function policy(bool $default_route = false, bool $own_networks = false): void
    {
        file_put_contents("{$this->dir}/policy.conf", "# Written by php artisan wg:install: what peers of any link may route (the root helper enforces it)\nallow_default_route=".($default_route ? 'true' : 'false')."\nallow_own_networks=".($own_networks ? 'true' : 'false')."\n");
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
            'WGLA_POLICY' => "{$this->dir}/policy.conf",
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

    /**
     * Make `wg pubkey` answer as wg does: the public key of the private key on its stdin (the
     * stub would print nothing). Nothing else of `wg` is stubbed then.
     */
    public function withPubkeys(): void
    {
        $php = escapeshellarg(PHP_BINARY);
        $code = escapeshellarg('echo base64_encode(sodium_crypto_scalarmult_base(base64_decode(trim(stream_get_contents(STDIN)))))."\n";');
        file_put_contents("{$this->dir}/stubs/wg", "#!/bin/bash\nif [ \"\$1\" = pubkey ]; then exec {$php} -r {$code}; fi\necho \"wg \$*: not stubbed\" >&2\nexit 1\n");
        chmod("{$this->dir}/stubs/wg", 0755);
    }

    /** A file in a link's client directory, as something other than the helper left it. */
    public function writeClient(string $link, string $name, string $content): string
    {
        if (! is_dir("{$this->confDir}/clients/{$link}")) {
            mkdir("{$this->confDir}/clients/{$link}", 0700, true);
        }
        file_put_contents($file = "{$this->confDir}/clients/{$link}/{$name}.conf", $content);

        return $file;
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

    private function addStub(string $name, bool $quiet = false): void
    {
        $log = $quiet ? 'lookups' : 'calls';
        $stub = <<<BASH
            #!/bin/bash
            # Records its argv and stdin, then prints/exits as configured by HelperSandbox::respond()
            name=\${0##*/}
            { printf '%s' "\$name"; printf '\\037%s' "\$@"; printf '\\n'; } >> "\$WGLA_SANDBOX/{$log}"
            BASH;
        $stub .= "\n".<<<'BASH'
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
