<?php

namespace App\Setup;

/**
 * Reads and edits KEY=value lines in a .env file, keeping everything else as it is. The
 * installer can't rely on config() here: it may be creating the file this process booted without.
 */
final class EnvFile
{
    public function __construct(public readonly string $path) {}

    public function exists(): bool
    {
        return is_file($this->path);
    }

    public function get(string $key): ?string
    {
        if (! $this->exists() || ! preg_match('/^'.preg_quote($key, '/').'=(.*)$/m', (string) file_get_contents($this->path), $m)) {
            return null;
        }

        $value = trim($m[1]);
        if (strlen($value) >= 2 && $value[0] === $value[-1] && in_array($value[0], ['"', "'"], true)) {
            $value = substr($value, 1, -1);
        }

        return $value;
    }

    public function set(string $key, string $value): void
    {
        $line = $key.'='.$this->format($value);
        $content = $this->exists() ? (string) file_get_contents($this->path) : '';
        $pattern = '/^'.preg_quote($key, '/').'=.*$/m';

        $content = preg_match($pattern, $content)
            ? preg_replace_callback($pattern, fn () => $line, $content, 1)
            : rtrim($content, "\n").($content === '' ? '' : "\n").$line."\n";

        file_put_contents($this->path, $content);
    }

    private function format(string $value): string
    {
        if (preg_match('/[\r\n]/', $value)) {
            throw new \InvalidArgumentException('A .env value cannot contain line breaks.');
        }

        return $value === '' || preg_match('/^[A-Za-z0-9_.:\/@+=,-]+$/', $value) ? $value : '"'.addcslashes($value, '"\\$').'"';
    }
}
