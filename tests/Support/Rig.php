<?php

namespace Tests\Support;

use App\Services\ConfigBuilder;
use App\Services\IpAllocator;
use App\Services\KeyManager;
use App\Services\Os\LinuxDriver;
use App\Services\Os\MacDriver;
use App\Services\WireGuard;
use App\Validation\WireGuardValidator;
use FilesystemIterator;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use Tests\Fakes\FakeHost;
use Tests\Fakes\FakeShell;

/**
 * The WireGuard service wired to a simulated Linux or macOS host (see FakeHost), with its own
 * temporary lock directory. Call Rig::cleanup() after each test.
 */
final class Rig
{
    public readonly FakeShell $shell;

    public readonly FakeHost $host;

    public readonly WireGuard $wg;

    public readonly string $tmp;

    /** @var list<string> */
    private static array $dirs = [];

    public function __construct(public readonly string $os)
    {
        $this->tmp = sys_get_temp_dir().'/wgla_test_'.bin2hex(random_bytes(6));
        mkdir($this->tmp, 0700, true);
        self::$dirs[] = $this->tmp;

        $config = array_merge(require dirname(__DIR__, 2).'/config/wireguard.php', ['hostname' => 'vpn.example.test']);

        $this->shell = new FakeShell;
        $driver = $os === 'mac' ? new MacDriver($this->shell, $config['helper']) : new LinuxDriver($this->shell, $config['helper']);
        $this->host = new FakeHost($os, $this->shell);

        $this->wg = new WireGuard(
            config: $config,
            os: $driver,
            validator: new WireGuardValidator,
            keys: new KeyManager,
            configBuilder: new ConfigBuilder($config, $driver),
            ipAllocator: new IpAllocator,
            lockPath: "{$this->tmp}/locks",
        );
    }

    /**
     * Remove the temporary directories of every rig created so far.
     */
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
                $entry->isDir() ? rmdir($entry->getPathname()) : unlink($entry->getPathname());
            }
            rmdir($dir);
        }

        self::$dirs = [];
    }
}
