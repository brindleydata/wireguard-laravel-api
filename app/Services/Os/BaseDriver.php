<?php

namespace App\Services\Os;

use App\Exceptions\SystemException;
use App\Services\ConfigBuilder;
use App\Services\Shell;

/**
 * Config and client-config file handling shared by both drivers.
 *
 * The web server user can't touch the config directory directly, so every operation goes through
 * sudo with commands that match the path-restricted sudoers rules shown by `wg:help`.
 */
abstract class BaseDriver implements OsDriver
{
    public function __construct(
        protected Shell $shell,
        protected string $stagingDir = '/tmp',
    ) {}

    public function publicIpv4(string $ip_service): ?string
    {
        return $this->shell->tryRun('curl -4 -s --max-time 5 :url', ['url' => $ip_service]);
    }

    public function publicIpv6(string $ip_service): ?string
    {
        return $this->shell->tryRun('curl -6 -s --max-time 5 :url', ['url' => $ip_service]);
    }

    public function writeConfig(string $name, string $content): void
    {
        $this->installFile($this->configPath()."/{$name}.conf", $content);
    }

    public function deleteConfig(string $name): void
    {
        $this->shell->tryRun('sudo rm -f :path', ['path' => $this->configPath()."/{$name}.conf"]);
    }

    public function readConfig(string $name): ?string
    {
        return $this->shell->tryRun('sudo cat :path', ['path' => $this->configPath()."/{$name}.conf"]);
    }

    public function configExists(string $name): bool
    {
        return $this->shell->tryRun('sudo test -f :path && echo 1', ['path' => $this->configPath()."/{$name}.conf"]) === '1';
    }

    public function listConfigNames(): array
    {
        $output = $this->shell->tryRun('sudo ls :path', ['path' => $this->configPath()]);
        if ($output === null || $output === '') {
            return [];
        }

        $names = [];
        foreach (explode("\n", trim($output)) as $file) {
            if (str_ends_with($file, '.conf')) {
                $names[] = basename($file, '.conf');
            }
        }

        return $names;
    }

    public function parseConfig(string $name): ?array
    {
        $content = $this->readConfig($name);

        return $content === null ? null : ConfigBuilder::parseMetadata($content);
    }

    public function writeClientConfig(string $link, string $key, string $content): void
    {
        $this->installFile($this->configPath()."/clients/{$link}/{$key}.conf", $content);
    }

    public function readClientConfig(string $link, string $key): ?string
    {
        return $this->shell->tryRun('sudo cat :path', ['path' => $this->configPath()."/clients/{$link}/{$key}.conf"]);
    }

    public function deleteClientConfig(string $link, string $key): void
    {
        $this->shell->tryRun('sudo rm -f :path', ['path' => $this->configPath()."/clients/{$link}/{$key}.conf"]);
    }

    public function deleteClientConfigDir(string $link): void
    {
        $this->shell->tryRun('sudo rm -rf :dir', ['dir' => $this->configPath()."/clients/{$link}"]);
    }

    /**
     * Write a root-owned 0600 file by staging it and copying it into place with sudo.
     */
    protected function installFile(string $path, string $content): void
    {
        $tmp = $this->stage($content);

        try {
            $this->shell->run('sudo mkdir -p :dir && sudo cp :tmp :path && sudo chmod 600 :path', [
                'dir' => dirname($path),
                'tmp' => $tmp,
                'path' => $path,
            ]);
        } finally {
            @unlink($tmp);
        }
    }

    /**
     * Create a private (0600) staging file and return its path.
     *
     * The path is built by hand instead of using tempnam(): sudoers only allows `cp /tmp/* ...`,
     * while tempnam() follows TMPDIR (/var/folders/... for macOS users) and resolves /tmp to
     * /private/tmp on macOS, so neither would match. Opening with 'x' (O_EXCL) refuses to follow
     * a planted symlink in the shared directory.
     */
    protected function stage(string $content): string
    {
        $handle = false;
        for ($attempt = 0; $attempt < 5 && $handle === false; $attempt++) {
            $path = $this->stagingDir.'/wgla_'.bin2hex(random_bytes(8));
            $handle = @fopen($path, 'x');
        }

        if ($handle === false) {
            throw new SystemException("Unable to create a staging file in {$this->stagingDir}");
        }

        try {
            chmod($path, 0600);
            fwrite($handle, $content."\n");
        } finally {
            fclose($handle);
        }

        return $path;
    }
}
