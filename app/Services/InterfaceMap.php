<?php

namespace App\Services;

class InterfaceMap
{
    protected array $map = [];

    public function __construct(
        protected string $mapFile,
    ) {
        $this->load();
    }

    /**
     * Resolve a friendly name to its OS interface name.
     * Returns the friendly name itself if no mapping exists (identity on Linux).
     */
    public function resolve(string $friendlyName): string
    {
        return $this->map[$friendlyName] ?? $friendlyName;
    }

    /**
     * Register a mapping from friendly name to OS interface name.
     */
    public function register(string $friendlyName, string $osName): void
    {
        $this->map[$friendlyName] = $osName;
        $this->save();
    }

    /**
     * Remove a mapping by friendly name.
     */
    public function unregister(string $friendlyName): void
    {
        unset($this->map[$friendlyName]);
        $this->save();
    }

    /**
     * Reverse lookup: find the friendly name for an OS interface name.
     */
    public function friendlyName(string $osName): ?string
    {
        $flipped = array_flip($this->map);

        return $flipped[$osName] ?? null;
    }

    /**
     * Get all mappings [friendlyName => osName].
     */
    public function all(): array
    {
        return $this->map;
    }

    protected function load(): void
    {
        if (! file_exists($this->mapFile)) {
            $this->map = [];

            return;
        }

        $content = file_get_contents($this->mapFile);
        $decoded = json_decode($content, true);
        $this->map = is_array($decoded) ? $decoded : [];
    }

    protected function save(): void
    {
        $dir = dirname($this->mapFile);
        if (! is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        file_put_contents(
            $this->mapFile,
            json_encode($this->map, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES)."\n",
        );
    }
}
