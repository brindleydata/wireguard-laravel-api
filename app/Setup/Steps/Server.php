<?php

namespace App\Setup\Steps;

use App\Services\Server as ServerService;
use App\Setup\Action;
use App\Setup\Context;
use App\Setup\EnvFile;
use App\Setup\Question;
use App\Setup\Step;

/**
 * Linux: the API as a systemd service running Octane + FrankenPHP as the web user. FrankenPHP
 * serves HTTPS itself (built-in Caddy), so there is no nginx or php-fpm to set up.
 */
class Server extends Step
{
    public const UNIT = '/etc/systemd/system/wgla.service';

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
                default: fn (Context $ctx) => $ctx->answer('domain') ?? (filter_var($ctx->answer('hostname'), FILTER_VALIDATE_IP) ? null : $ctx->answer('hostname')),
                when: $tls('letsencrypt'),
                validate: fn ($value) => filter_var($value, FILTER_VALIDATE_IP) || ! preg_match('/^([a-z0-9-]+\.)+[a-z]{2,}$/i', (string) $value)
                    ? "Let's Encrypt needs a domain name that points to this server, not an IP address." : null,
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

    public function check(Context $ctx): array
    {
        $problems = [];
        if (! is_executable($ctx->app('frankenphp'))) {
            $problems[] = 'FrankenPHP is not downloaded';
        }

        if (! $this->unitCurrent($ctx)) {
            $problems[] = 'The wgla service is not installed, or its settings changed';
        } elseif (! $this->running()) {
            $problems[] = 'The wgla service is not enabled and running';
        } elseif ($this->stale($ctx)) {
            $problems[] = 'The API still runs the code from before the last deploy';
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
            $actions[] = Action::command('Download FrankenPHP', 'cd '.self::q($ctx->app()).' && '.self::q($ctx->php).' artisan octane:install --server=frankenphp --no-interaction');
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

        // Octane reloads its workers without dropping connections
        return $this->stale($ctx) ? [...$actions, Action::command('Reload the API with the code on disk', 'sudo systemctl reload wgla')] : $actions;
    }

    public function manual(Context $ctx): string
    {
        return "Make the certificate and key readable by {$ctx->webUser()} (e.g. a group it belongs to), or copy them somewhere it can read.";
    }

    protected function unitCurrent(Context $ctx): bool
    {
        $unit = $ctx->system(self::UNIT);

        return is_file($unit) && file_get_contents($unit) === $this->unit($ctx);
    }

    protected function running(): bool
    {
        return $this->shell->tryRun('systemctl is-enabled wgla') === 'enabled' && $this->shell->tryRun('systemctl is-active wgla') === 'active';
    }

    /**
     * Whether the API serves different code than what's on disk: it reports the fingerprint it
     * booted with in /status. Unknown (API not answering, no key) counts as not stale.
     */
    protected function stale(Context $ctx): bool
    {
        $key = (new EnvFile($ctx->app('.env')))->get('API_KEY');
        if (! $key) {
            return false;
        }

        [$url, $options] = $this->localUrl($ctx);
        // The key goes in on stdin, not on the command line where other users could see it
        $body = $this->shell->tryRun(trim("curl -s --max-time 3 {$options}").' -H @- :url', ['url' => "{$url}/status"], "api-key: {$key}\n");
        $running = $body === null ? null : (json_decode($body, true)['app']['code'] ?? null);

        return $running !== null && $running !== ServerService::codeFingerprint($ctx->app());
    }

    /** The systemd unit for the current answers. */
    public function unit(Context $ctx): string
    {
        $app = $ctx->app();
        $port = (string) $ctx->answer('port', '443');
        $tls = $ctx->answer('tls');

        [$site, $directive, $host] = match ($tls) {
            'letsencrypt' => ['https://'.$ctx->answer('domain').($port === '443' ? '' : ":{$port}"), '', '0.0.0.0'],
            'cert' => [":{$port}", 'tls '.$ctx->answer('cert').' '.$ctx->answer('key'), '0.0.0.0'],
            default => ['http://'.$ctx->answer('bind', '127.0.0.1').":{$port}", '', (string) $ctx->answer('bind', '127.0.0.1')],
        };
        $https = $tls === 'http' ? '' : ' --https';

        return <<<UNIT
            [Unit]
            Description=WireGuard Laravel API
            After=network.target

            [Service]
            User={$ctx->webUser()}
            Group={$ctx->webGroup()}
            WorkingDirectory={$app}
            Environment=XDG_DATA_HOME={$app}/storage/framework/caddy XDG_CONFIG_HOME={$app}/storage/framework/caddy
            Environment="WGLA_SITE_ADDRESS={$site}"
            Environment="WGLA_TLS_DIRECTIVE={$directive}"
            ExecStart={$ctx->php} {$app}/artisan octane:start --server=frankenphp --host={$host} --port={$port} --admin-port=2019{$https} --caddyfile={$app}/deploy/Caddyfile
            ExecReload={$ctx->php} {$app}/artisan octane:reload --server=frankenphp
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
            'cert' => 'https://'.$ctx->answer('hostname').($port === '443' ? '' : ":{$port}"),
            default => 'http://'.$ctx->answer('bind', '127.0.0.1').":{$port} (behind your proxy)",
        };
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
            default => ['http://'.$ctx->answer('bind', '127.0.0.1').":{$port}", ''],
        };
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
