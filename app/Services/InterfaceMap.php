<?php

namespace App\Services;

class InterfaceMap
{
    protected array $map = [];

    public function __construct(
        protected string $map_file,
    ) {
        $this->load();
    }

    /**
     * Resolve a friendly name to its OS interface name.
     * Returns the friendly name itself if no mapping exists (identity on Linux).
     */
    public function resolve(string $friendly_name): string
    {
        return $this->map[$friendly_name] ?? $friendly_name;
    }

    /**
     * Register a mapping from friendly name to OS interface name.
     */
    public function register(string $friendly_name, string $os_name): void
    {
        $this->map[$friendly_name] = $os_name;
        $this->save();
    }

    /**
     * Remove a mapping by friendly name.
     */
    public function unregister(string $friendly_name): void
    {
        unset($this->map[$friendly_name]);
        $this->save();
    }

    /**
     * Reverse lookup: find the friendly name for an OS interface name.
     */
    public function friendlyName(string $os_name): ?string
    {
        $flipped = array_flip($this->map);

        return $flipped[$os_name] ?? null;
    }

    /**
     * Get all mappings [friendly_name => os_name].
     */
    public function all(): array
    {
        return $this->map;
    }

    protected function load(): void
    {
        if (! file_exists($this->map_file)) {
            $this->map = [];

            return;
        }

        $content = file_get_contents($this->map_file);
        $decoded = json_decode($content, true);
        $this->map = is_array($decoded) ? $decoded : [];
    }

    protected function save(): void
    {
        $dir = dirname($this->map_file);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents(
            $this->map_file,
            json_encode($this->map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
        );
    }
}
