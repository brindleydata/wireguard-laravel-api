<?php

namespace App\Setup\Steps;

use App\Services\Server as ServerService;
use App\Setup\Action;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Question;
use App\Setup\Step;
use Illuminate\Support\Sleep;
use Laravel\Octane\Commands\StartFrankenPhpCommand;
use ReflectionClass;

/**
 * Linux: the API as a systemd service running Octane + FrankenPHP as the web user. FrankenPHP
 * serves HTTPS itself (built-in Caddy), so there is no nginx or php-fpm to set up.
 */
class Server extends Step
{
    public const UNIT = '/etc/systemd/system/wgla.service';

    /** FrankenPHP's admin API, which Octane reloads workers through. Caddy's default too. */
    public const ADMIN_PORT = 2019;

    /** How often the API is asked, a second apart, for the code on disk after its fix (recheck()). */
    public const SETTLE_ATTEMPTS = 20;

    /**
     * The service's PATH after the app directory, which comes first. Octane runs the first
     * `frankenphp` on the PATH and only then looks in the app (FindsFrankenPhpBinary): one that
     * FrankenPHP's own installer put in /usr/local/bin would run instead of the one this step
     * downloads, checks and restarts with. (The app calls sudo with a PATH of its own: Shell.)
     */
    public const SERVICE_PATH = '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin';

    /**
     * Where FrankenPHP's releases are downloaded from. Not through api.github.com, as Octane's own
     * installer does: without a token that is limited to 60 requests an hour per IP address,
     * which CI runners, offices and cloud NAT gateways share. Then nothing could be installed.
     */
    public const RELEASES = 'https://github.com/php/frankenphp/releases';

    public function key(): string
    {
        return 'server';
    }

    public function title(): string
    {
        return 'API server (Octane + FrankenPHP)';
    }

    public function applies(Context $ctx): bool
    {
        return ! $ctx->isMac();
    }

    public function questions(Context $ctx): array
    {
        $tls = fn (string ...$modes) => fn (Context $ctx) => in_array($ctx->answer('tls'), $modes, true);

        return [
            new Question(
                key: 'tls',
                label: 'How should the API serve HTTPS?',
                type: 'select',
                default: fn (Context $ctx) => $ctx->answer('tls'),
                options: [
                    'letsencrypt' => "Let's Encrypt certificate for a domain name",
                    'cert' => 'My own certificate and key files',
                    'http' => 'Plain HTTP on a local port, behind my own reverse proxy that does TLS',
                ],
            ),
            new Question(
                key: 'domain',
                label: 'Domain name for the certificate',
                // The machine's name, when it is one
                default: fn (Context $ctx) => $ctx->answer('domain') ?? (self::isDomainName($this->hostname()) ? $this->hostname() : null),
                when: $tls('letsencrypt'),
                validate: fn ($value) => self::isDomainName((string) $value)
                    ? null : "Let's Encrypt needs a domain name that points to this server, not an IP address.",
                hint: "It must point to this server, and port 443 (or 80) must be reachable from the internet for Let's Encrypt.",
            ),
            // Checked as root: certificate directories are often closed to the installer user
            new Question(key: 'cert', label: 'Certificate file (PEM, full chain)', when: $tls('cert'), validate: fn ($value) => $this->fileExists((string) $value) ? null : 'No such file.'),
            new Question(key: 'key', label: 'Private key file (PEM)', when: $tls('cert'), validate: fn ($value) => $this->fileExists((string) $value) ? null : 'No such file.'),
            new Question(
                key: 'bind',
                label: 'Address to listen on (your proxy connects here)',
                default: '127.0.0.1',
                when: $tls('http'),
                validate: fn ($value) => filter_var($value, FILTER_VALIDATE_IP) ? null : 'Not an IP address.',
            ),
            new Question(
                key: 'port',
                label: 'Port',
                default: fn (Context $ctx) => $ctx->answer('port') ?? ($ctx->answer('tls') === 'http' ? '8080' : '443'),
                validate: fn ($value) => ctype_digit((string) $value) && $value >= 1 && $value <= 65535 ? null : 'Not a port number.',
                warning: fn ($value, Context $ctx) => $ctx->answer('tls') !== 'http' && (string) $value !== '443' ? $this->nonStandardPort((string) $value, $ctx) : null,
            ),
        ];
    }

    /**
     * The admin port isn't asked for: it stays what the installed service uses, and a new
     * install takes 2019 unless something else has it (a Caddy reverse proxy on this host does),
     * then the next free port. `--admin-port=` sets it by hand.
     */
    public function after(Context $ctx): void
    {
        if ($ctx->answer('admin_port') === null) {
            $ctx->answers['admin_port'] = (string) ($this->installedAdminPort($ctx) ?? $this->freeAdminPort($ctx));
        }
    }

    public function check(Context $ctx): array
    {
        $problems = [];
        if (! is_executable($ctx->app('frankenphp'))) {
            $problems[] = 'FrankenPHP is not downloaded';
        } elseif (($outdated = $this->outdatedFrankenPhp($ctx)) !== null) {
            $problems[] = "FrankenPHP {$outdated[0]} is older than this version of Octane needs ({$outdated[1]}): the service would not start again";
        }

        if (! $this->unitCurrent($ctx)) {
            $problems[] = $this->onlyCaddyfileChanged($ctx)
                ? 'deploy/Caddyfile changed: the API only reads it when it starts'
                : 'The wgla service is not installed, or its settings changed';
        } elseif (! $this->running()) {
            $problems[] = 'The wgla service is not enabled and running';
        } elseif (($stale = $this->staleness($ctx)) !== null) {
            $problems[] = $stale[1];
        }

        if ($ctx->answer('tls') === 'cert' && $ctx->separateWebUser()) {
            foreach (['cert', 'key'] as $file) {
                if (! $this->webUserCan($ctx, '-r', (string) $ctx->answer($file))) {
                    $problems[] = "{$ctx->webUser()} can't read ".$ctx->answer($file);
                }
            }
        }

        return $problems;
    }

    public function plan(Context $ctx): array
    {
        $actions = [];
        if (! is_executable($ctx->app('frankenphp'))) {
            $actions[] = Action::command('Download FrankenPHP', $this->downloadFrankenPhp($ctx));
        } elseif ($this->outdatedFrankenPhp($ctx) !== null) {
            $actions[] = Action::command('Download the current FrankenPHP (the installed one stays if that fails)', $this->downloadFrankenPhp($ctx));
            if ($this->unitCurrent($ctx) && $this->running()) {
                // A reload only restarts the workers inside the running binary
                return [...$actions, Action::command('Restart the API with it', 'sudo systemctl restart wgla')];
            }
        }

        $unit = self::q($ctx->system(self::UNIT));

        if (! $this->unitCurrent($ctx) || ! $this->running()) {
            return [
                ...$actions,
                Action::command('Install the systemd service', '(tmp=$(mktemp) && printf \'%s\' '.self::q($this->unit($ctx)).' > "$tmp"'
                    ." && sudo install -o root -g root -m 644 \"\$tmp\" {$unit}; status=\$?; rm -f \"\$tmp\"; exit \$status)"),
                Action::command('Start it now and at boot', 'sudo systemctl daemon-reload && sudo systemctl enable wgla 2> /dev/null && sudo systemctl restart wgla'),
            ];
        }

        return match ($this->staleness($ctx)[0] ?? null) {
            // Octane reloads its workers without dropping connections
            'code' => [...$actions, Action::command('Reload the API with the code on disk', 'sudo systemctl reload wgla')],
            // A restart picks up new settings even on a server started before .env stayed out of
            // the process environment (bootstrap/app.php), where a reload would keep the old ones
            'key' => [...$actions, Action::command('Restart the API with the settings on disk', 'sudo systemctl restart wgla')],
            // Hanging, failing or not up: whatever it runs, a restart runs what's on disk
            'down', 'unknown' => [...$actions, Action::command('Restart the API with the code on disk', 'sudo systemctl restart wgla')],
            default => $actions,
        };
    }

    /**
     * After the fix, the API may not serve the code on disk yet: a restarted one takes a moment
     * to start, and `systemctl reload` (octane:reload) returns before the workers have restarted.
     * So it is asked again for a while (bounded) before it counts as a problem that remains.
     */
    public function recheck(Context $ctx): array
    {
        for ($attempt = 1; $attempt < self::SETTLE_ATTEMPTS && $this->settling($ctx); $attempt++) {
            Sleep::for(1)->second();
        }

        return $this->check($ctx);
    }

    /** Whether the service is installed as it should be, but doesn't serve the code on disk (yet). */
    protected function settling(Context $ctx): bool
    {
        return $this->unitCurrent($ctx) && (! $this->running() || in_array($this->staleness($ctx)[0] ?? null, ['code', 'down', 'unknown'], true));
    }

    public function manual(Context $ctx): string
    {
        return implode(' ', array_filter([
            (new EnvFile($ctx->app('.env')))->get('API_KEY') ? null : 'Set API_KEY in .env (php artisan wg:install --step=environment does).',
            $ctx->answer('tls') === 'cert' ? "Make the certificate and key readable by {$ctx->webUser()} (e.g. a group it belongs to), or copy them somewhere it can read." : null,
        ]));
    }

    /**
     * Download the current FrankenPHP release into the app, in place of an installed one. The new
     * binary only takes its place once it is complete and runs, so a failed download leaves
     * things as they were. The one it replaces stays as frankenphp.previous (a hard link, no
     * copy): the way back from a failed update puts it back (Updater::restoreFrankenPhp()).
     */
    public function downloadFrankenPhp(Context $ctx): string
    {
        $url = self::q(self::RELEASES.'/latest/download/'.$this->frankenPhpAsset($ctx));

        return '(cd '.self::q($ctx->app())." && curl -fsSL --retry 3 --retry-delay 2 -o frankenphp.new {$url}"
            .' && chmod 755 frankenphp.new && ./frankenphp.new version > /dev/null'
            .' && { [ ! -e frankenphp ] || ln -f frankenphp frankenphp.previous; } && mv -f frankenphp.new frankenphp'
            .' || { rm -f frankenphp.new; exit 1; })';
    }

    /**
     * The release asset for this machine, named as Octane's installer names them (OctaneTest
     * checks that against its source): a glibc build where there is glibc, else the static one.
     */
    protected function frankenPhpAsset(Context $ctx): string
    {
        $arch = php_uname('m');
        if ($ctx->isMac()) {
            return "frankenphp-mac-{$arch}";
        }

        return 'frankenphp-linux-'.$arch.($this->shell->tryRun('getconf GNU_LIBC_VERSION') === null ? '' : '-gnu');
    }

    /** The installed binary's version (1.13.2), or null when there is none or it doesn't say. */
    public function frankenPhpVersion(Context $ctx): ?string
    {
        $version = is_executable($ctx->app('frankenphp')) ? $this->shell->tryRun(':bin version', ['bin' => $ctx->app('frankenphp')]) : null;

        return $version !== null && preg_match('/FrankenPHP v?(\d+\.\d+\.\d+)/', $version, $m) ? $m[1] : null;
    }

    /**
     * The current release's version, or null when GitHub can't be asked: read from where
     * …/releases/latest redirects to, which needs no API either.
     */
    public function latestFrankenPhp(): ?string
    {
        $url = $this->shell->tryRun("curl -fsS -o /dev/null -w '%{redirect_url}' --max-time 10 :url", ['url' => self::RELEASES.'/latest']);

        return $url !== null && preg_match('#/tag/v?(\d+\.\d+\.\d+)$#', $url, $m) ? $m[1] : null;
    }

    /**
     * [installed, required] when the binary is older than Octane's minimum. Octane then wants to
     * replace it when the service starts, which the web user can't (the code is read-only for
     * it), so the service wouldn't come up again. Null when it is recent enough, or unknown.
     *
     * @return array{0: string, 1: string}|null
     */
    protected function outdatedFrankenPhp(Context $ctx): ?array
    {
        $required = class_exists(StartFrankenPhpCommand::class)
            ? ((new ReflectionClass(StartFrankenPhpCommand::class))->getDefaultProperties()['requiredFrankenPhpVersion'] ?? null)
            : null;
        $installed = $this->frankenPhpVersion($ctx);

        return is_string($required) && $installed !== null && version_compare($installed, $required, '<') ? [$installed, $required] : null;
    }

    /** The admin port of the service as it is installed, so a re-run or an update doesn't move it. */
    protected function installedAdminPort(Context $ctx): ?int
    {
        $unit = $ctx->system(self::UNIT);

        return is_file($unit) && preg_match('/--admin-port=(\d+)/', (string) file_get_contents($unit), $m) ? (int) $m[1] : null;
    }

    protected function freeAdminPort(Context $ctx): int
    {
        for ($port = self::ADMIN_PORT; $port < self::ADMIN_PORT + 100; $port++) {
            if ((string) $port !== (string) $ctx->answer('port') && $this->portFree($port)) {
                return $port;
            }
        }

        return self::ADMIN_PORT;
    }

    /** Whether nothing listens on a local port: can we bind it ourselves? */
    protected function portFree(int $port): bool
    {
        $socket = @stream_socket_server("tcp://127.0.0.1:{$port}");
        if ($socket === false) {
            return false;
        }
        fclose($socket);

        return true;
    }

    protected function unitCurrent(Context $ctx): bool
    {
        $unit = $ctx->system(self::UNIT);

        return is_file($unit) && file_get_contents($unit) === $this->unit($ctx);
    }

    /** Whether the installed unit is the current one but for the Caddyfile it names. */
    protected function onlyCaddyfileChanged(Context $ctx): bool
    {
        $unit = $ctx->system(self::UNIT);
        $other = fn (string $unit) => preg_replace('/^# Caddyfile .*$/m', '', $unit);

        return is_file($unit) && $other((string) file_get_contents($unit)) === $other($this->unit($ctx));
    }

    protected function running(): bool
    {
        return $this->shell->tryRun('systemctl is-enabled wgla') === 'enabled' && $this->shell->tryRun('systemctl is-active wgla') === 'active';
    }

    /**
     * How the running API differs from what's on disk, as [kind, problem], asked through /status
     * (which reports the code fingerprint it booted with). Kinds: 'code' (other code), 'key' (it
     * refuses the API key in .env: it started with another one), 'down' (no answer), 'unknown'
     * (an answer that doesn't say which code: an error, or not the API), 'nokey' (no API_KEY in
     * .env to ask with). Null only when it says it runs the code on disk: an API that can't be
     * asked is not taken for current.
     *
     * @return array{0: string, 1: string}|null
     */
    protected function staleness(Context $ctx): ?array
    {
        $key = (new EnvFile($ctx->app('.env')))->get('API_KEY');
        if (! $key) {
            return ['nokey', 'There is no API_KEY in .env to ask the API which code it runs'];
        }

        [$url, $options] = $this->localUrl($ctx);
        // The key goes in on stdin, not on the command line where other users could see it
        // -w: the status code on a line of its own after the body (curl expands the \n)
        $output = $this->shell->tryRun(trim("curl -s --max-time 3 {$options}").' -w \'\n%{http_code}\' -H @- :url', ['url' => "{$url}/status"], "api-key: {$key}\n");
        if ($output === null) {
            return ['down', "The API doesn't answer at {$url}/status, so it can't be told which code it runs"];
        }

        $lines = explode("\n", $output);
        $status = array_pop($lines);
        if ($status === '403') {
            return ['key', "The API doesn't take the API key in .env: it still runs with its old settings"];
        }
        $running = json_decode(implode("\n", $lines), true)['app']['code'] ?? null;

        return match (true) {
            ! is_string($running) || $status !== '200' => ['unknown', "The API doesn't say which code it runs ({$url}/status answers {$status})"],
            $running !== ServerService::codeFingerprint($ctx->app()) => ['code', 'The API still runs the code from before the last deploy'],
            default => null,
        };
    }

    /** The systemd unit for the current answers. */
    public function unit(Context $ctx): string
    {
        $app = $ctx->app();
        $port = (string) $ctx->answer('port', '443');
        $admin = (string) $ctx->answer('admin_port', self::ADMIN_PORT);
        $tls = $ctx->answer('tls');

        // Behind a proxy: listening on the bind address only (`bind`), for any Host header. In a
        // site address an IP is only a Host matcher, and Caddy listens on every interface: the
        // API would be open to all, over plain HTTP, and a proxy that passes on the client's
        // Host header would get nothing
        [$site, $directive, $bind, $host] = match ($tls) {
            'letsencrypt' => ['https://'.$ctx->answer('domain').($port === '443' ? '' : ":{$port}"), '', '', '0.0.0.0'],
            'cert' => [":{$port}", 'tls '.$ctx->answer('cert').' '.$ctx->answer('key'), '', '0.0.0.0'],
            default => ["http://:{$port}", '', 'bind '.$this->bindHost($ctx), (string) $ctx->answer('bind', '127.0.0.1')],
        };
        $https = $tls === 'http' ? '' : ' --https';
        $path = self::SERVICE_PATH;
        // A new Caddyfile is a new unit, which the service is restarted with (plan())
        $caddyfile = "{$app}/deploy/Caddyfile";
        $caddyfileHash = is_file($caddyfile) ? 'sha256:'.hash_file('sha256', $caddyfile) : 'missing';

        return <<<UNIT
            [Unit]
            Description=WireGuard Laravel API
            After=network.target

            [Service]
            User={$ctx->webUser()}
            Group={$ctx->webGroup()}
            WorkingDirectory={$app}
            # The app's own frankenphp, not another one on the PATH
            Environment="PATH={$app}:{$path}"
            Environment=XDG_DATA_HOME={$app}/storage/framework/caddy XDG_CONFIG_HOME={$app}/storage/framework/caddy
            Environment="WGLA_SITE_ADDRESS={$site}"
            Environment="WGLA_TLS_DIRECTIVE={$directive}"
            Environment="WGLA_BIND_DIRECTIVE={$bind}"
            ExecStart={$ctx->php} {$app}/artisan octane:start --server=frankenphp --host={$host} --port={$port} --admin-port={$admin}{$https} --caddyfile={$caddyfile}
            ExecReload={$ctx->php} {$app}/artisan octane:reload --server=frankenphp
            # A reload doesn't read the Caddyfile again, a restart does: a new one changes this line
            # Caddyfile {$caddyfileHash}
            Restart=on-failure
            # Bind ports below 1024 without root. Never add NoNewPrivileges: it would break sudo to the root helper.
            AmbientCapabilities=CAP_NET_BIND_SERVICE

            [Install]
            WantedBy=multi-user.target

            UNIT;
    }

    /** Where clients reach the API. */
    public function publicUrl(Context $ctx): string
    {
        $port = (string) $ctx->answer('port', '443');

        return match ($ctx->answer('tls')) {
            'letsencrypt' => 'https://'.$ctx->answer('domain').($port === '443' ? '' : ":{$port}"),
            'cert' => 'https://'.$this->hostname().($port === '443' ? '' : ":{$port}"),
            default => 'http://'.$this->bindHost($ctx).":{$port} (behind your proxy)",
        };
    }

    /** The machine's name. */
    protected function hostname(): string
    {
        return (string) gethostname();
    }

    /** A name in DNS (a.example, also an IDN's xn--… labels), not an IP address. */
    protected static function isDomainName(string $name): bool
    {
        return ! filter_var($name, FILTER_VALIDATE_IP) && preg_match('/^([a-z0-9-]+\.)+[a-z0-9-]*[a-z][a-z0-9-]*$/i', $name) === 1;
    }

    /**
     * How to reach the API from this machine: [url, extra curl options].
     *
     * @return array{0: string, 1: string}
     */
    public function localUrl(Context $ctx): array
    {
        $port = (string) $ctx->answer('port', '443');

        return match ($ctx->answer('tls')) {
            'letsencrypt' => ['https://'.$ctx->answer('domain').":{$port}", '--resolve '.self::q($ctx->answer('domain').":{$port}:127.0.0.1")],
            'cert' => ["https://127.0.0.1:{$port}", '-k'],
            default => ['http://'.$this->bindHost($ctx).":{$port}", ''],
        };
    }

    /** The address the API listens on (behind a proxy), as a URL has it: IPv6 in brackets. */
    protected function bindHost(Context $ctx): string
    {
        $bind = (string) $ctx->answer('bind', '127.0.0.1');

        return str_contains($bind, ':') ? "[{$bind}]" : $bind;
    }

    protected function fileExists(string $path): bool
    {
        return is_file($path) || $this->asRoot('test -f :path', ['path' => $path]) !== null;
    }

    protected function nonStandardPort(string $port, Context $ctx): string
    {
        $lines = [
            "Port {$port} instead of the standard 443 means:",
            "  - clients must add :{$port} to the API URL",
            '  - firewalls and proxies on the way often block unusual ports',
            "  - it must be open in this server's firewall as well",
        ];
        if ($ctx->answer('tls') === 'letsencrypt') {
            $lines[] = "  - Let's Encrypt still needs port 443 or 80 reachable to issue and renew the certificate";
        }

        return implode("\n", $lines);
    }
}
