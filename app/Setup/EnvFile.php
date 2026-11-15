<?php

namespace App\Setup;

use Dotenv\Dotenv;
use Dotenv\Exception\InvalidFileException;

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

    /**
     * A value as Laravel reads it, through phpdotenv's own parser: unquoted up to a space or `#`
     * (a comment), 'single-quoted' as it is, "double-quoted" with \" \\ \$ \n … undone. Like
     * dotenv, the last line for a key counts. ${OTHER} isn't filled in. A line dotenv can't read
     * (Laravel wouldn't boot) is taken as it stands, minus surrounding quotes.
     */
    public function get(string $key): ?string
    {
        $line = $this->exists() ? $this->line((string) file_get_contents($this->path), $key) : null;
        if ($line === null) {
            return null;
        }

        try {
            return Dotenv::parse($line[0])[$key] ?? '';
        } catch (InvalidFileException) {
            $value = trim(substr($line[0], strpos($line[0], '=') + 1));

            return strlen($value) >= 2 && $value[0] === $value[-1] && in_array($value[0], ['"', "'"], true) ? substr($value, 1, -1) : $value;
        }
    }

    /**
     * Set a key: its line is replaced (the one that counts, when there are several), or a line is
     * added. Written in place, never through a new file: that would lose the group `sudo chgrp`
     * gave .env, which the deploy user can't set again.
     */
    public function set(string $key, string $value): void
    {
        $line = $key.'='.$this->format($value);
        $content = $this->exists() ? (string) file_get_contents($this->path) : '';

        $content = ($old = $this->line($content, $key)) !== null
            ? substr_replace($content, $line, $old[1], strlen($old[0]))
            : rtrim($content, "\n").($content === '' ? '' : "\n").$line."\n";

        file_put_contents($this->path, $content);
    }

    /**
     * The last line that sets $key, as dotenv finds it (`export` and spaces around `=` allowed),
     * with its offset.
     *
     * @return array{0: string, 1: int}|null
     */
    private function line(string $content, string $key): ?array
    {
        preg_match_all('/^[ \t]*(?:export[ \t]+)?'.preg_quote($key, '/').'[ \t]*=.*$/m', $content, $matches, PREG_OFFSET_CAPTURE);

        return $matches[0] === [] ? null : end($matches[0]);
    }

    private function format(string $value): string
    {
        if (preg_match('/[\r\n]/', $value)) {
            throw new \InvalidArgumentException('A .env value cannot contain line breaks.');
        }

        return $value === '' || preg_match('/^[A-Za-z0-9_.:\/@+=,-]+$/', $value) ? $value : '"'.addcslashes($value, '"\\$').'"';
    }
}
