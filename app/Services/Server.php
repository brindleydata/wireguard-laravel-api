<?php

namespace App\Services;

use App\DTOs\SystemStatus;
use App\Services\Os\OsDriver;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

class Server
{
    /** The code this process (an Octane worker: for its whole life) booted with. */
    protected static ?string $runningCode = null;

    /** Seconds a healthy answer is good for. */
    protected const HEALTHY_FOR = 5;

    protected int $healthyUntil = 0;

    public function __construct(
        protected OsDriver $os,
    ) {}

    /**
     * Identifies the code on disk by content: the PHP code, the installed packages and .env (well
     * under 1 MB). Any deploy that changes something changes it, including going back to older
     * code; touching files without changing them doesn't.
     */
    public static function codeFingerprint(string $base): string
    {
        $files = [];
        foreach (['app', 'config', 'routes'] as $dir) {
            if (is_dir("{$base}/{$dir}")) {
                foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator("{$base}/{$dir}", FilesystemIterator::SKIP_DOTS)) as $file) {
                    $files[] = $file->getPathname();
                }
            }
        }
        foreach (['bootstrap/app.php', 'bootstrap/providers.php', 'public/frankenphp-worker.php', 'composer.lock', 'vendor/composer/installed.json', '.env'] as $file) {
            $files[] = "{$base}/{$file}";
        }
        sort($files);

        $lines = [];
        foreach ($files as $file) {
            $lines[] = substr($file, strlen($base)).':'.(is_file($file) ? hash_file('xxh128', $file) : '-');
        }

        return substr(hash('sha256', implode("\n", $lines)), 0, 16);
    }

    /**
     * Remember the code this process booted with. Octane workers boot once and keep serving it,
     * so the installer can tell when a deploy (e.g. a plain git pull) still needs a reload.
     */
    public static function rememberRunningCode(string $base): void
    {
        self::$runningCode = self::codeFingerprint($base);
    }

    public function status(): SystemStatus
    {
        $hostname = config('wireguard.hostname') ?? gethostname();

        return new SystemStatus(
            app: [
                'name' => config('app.name'),
                'version' => config('app.version', 'dev'),
                'code' => self::$runningCode,
            ],
            cpu: $this->os->cpu(),
            ram: $this->os->ram(),
            disk: $this->os->disk(),
            hostname: $hostname,
            helper: $this->os->helperStatus(),
        );
    }

    public function ip(): array
    {
        $ip_service = config('wireguard.ip_service', 'http://ifconfig.me/ip');

        return [
            'ipv4' => $this->os->publicIpv4($ip_service),
            'ipv6' => $this->os->publicIpv6($ip_service),
        ];
    }

    /** The user this process runs as. */
    public function processUser(): string
    {
        return function_exists('posix_getpwuid') ? (posix_getpwuid(posix_geteuid())['name'] ?? '') : get_current_user();
    }

    /**
     * Whether the API can do its job: the root helper is installed, current and allowed by sudo.
     *
     * /health is public and asking means running sudo, so a healthy answer is kept for a few
     * seconds (by this instance: an Octane worker). An unhealthy one never is: once the cause is
     * fixed, the next request says so.
     */
    public function healthy(): bool
    {
        if (time() < $this->healthyUntil) {
            return true;
        }

        $healthy = $this->os->helperStatus()['state'] === 'ok';
        if ($healthy) {
            $this->healthyUntil = time() + self::HEALTHY_FOR;
        }

        return $healthy;
    }

    public function interfaces(): array
    {
        return $this->os->networkInterfaces();
    }
}
