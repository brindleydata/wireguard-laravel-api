<?php

namespace App\Services;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Exception;

/**
 * Host utils.
 * @todo OS-dependent stuff
 */
class Host
{
    /**
     * For now, Linux only
     */
    public function __construct(
        private string $ipservice = 'http://ifconfig.me/ip',
    ) {
        if (!str_contains($this->os(), 'Linux')) {
            throw new Exception('The only operating system supported is Linux.');
        }
    }

    /**
     * Runs commands through the system shell.
     */
    public function cmd(string $cmd, string $cwd = null, array $env = null, mixed $input = null, ?float $timeout = 60, bool $as_array = false): string|array
    {
        $process = Process::fromShellCommandline($cmd, $cwd, $env, $input, $timeout);
        $process->run();
        if (!$process->isSuccessful()) {
            throw new ProcessFailedException($process);
        }

        $out = $process->getOutput();

        if ($as_array) {
            return explode("\n", $out);
        }

        return $out;
    }

    /**
     * Returns current OS name.
     */
    public function os(): string
    {
        return $this->cmd('uname');
    }

    /**
     * Returns CPU info: cores, load (avg) and usage (in percents).
     */
    public function cpu(): array
    {
        $cores = (int) $this->cmd('nproc');
        $load = (float) preg_replace('~\s.+~', '', $this->cmd('cat /proc/loadavg'));
        $usage = (int) round($load / $cores * 100);

        return compact('cores', 'load', 'usage');
    }

    /**
     * Returns RAM info: total and free amounts (in kB) and usage (in percents).
     */
    public function ram(): array
    {
        $total = 0;
        $free = 0;
        $usage = 0;

        $memlines = $this->cmd('cat /proc/meminfo', as_array: true);
        foreach ($memlines as $line) {
            list($name, $value) = preg_split('~:\s+~', $line);
            if ($name == 'MemTotal') {
                $total = (int) $value;
            } elseif ($name == 'MemFree') {
                $free = (int) $value;
            }

            if ($total && $free) {
                break;
            }
        }

        $usage = round($free / $total * 100);
        return compact('total', 'free', 'usage');
    }

    /**
     * Returns disk partition info.
     */
    public function disk(string $partition = '/'): array
    {
        $df = $this->cmd("df {$partition}", as_array: true)[1];
        [$part, $size, , $free, $usage ] = preg_split('~\s+~', $df);
        return [
            'partition' => $part,
            'size' => (int) $size,
            'free' => (int) $free,
            'usage' => (int) preg_replace('~\s*%~', '', $usage),
        ];
    }

    /**
     * Returns public IP address using remote service.
     */
    public function ip(string $ifname = null, string $ipservice = null): string
    {
        if (!$ipservice)
            $ipservice = $this->ipservice;

        $cmd = "curl {$ipservice}";
        if ($ifname)
            $cmd = "curl -s --interface {$ifname} {$ipservice}";

        return $this->cmd($cmd);
    }

    /**
     * Returns list of network links.
     */
    public function links(): array
    {
        $links = [];
        $lines = $this->cmd('ip link show', as_array: true);
        foreach ($lines as $line) {
            if (preg_match('/^\d+: (?<link>\w+):/', $line, $matches)) {
                $links []= $matches['link'];
            }
        }

        return $links;
    }

    /**
     * Returns combined status.
     */
    public function status(): array
    {
        return [
            'app' => ['name' => env('APP_NAME'), 'version' => env('APP_VERSION')],
            'cpu' => $this->cpu(),
            'ram' => $this->ram(),
            'disk' => $this->disk(),
            'endpoint' => $this->ip(),
        ];
    }
}
