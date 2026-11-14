<?php

namespace App\Setup\Steps;

use App\Setup\Action;
use App\Setup\Context;
use App\Setup\Step;

class Packages extends Step
{
    public function key(): string
    {
        return 'packages';
    }

    public function title(): string
    {
        return 'System packages';
    }

    public function check(Context $ctx): array
    {
        return array_map(fn (string $what, string $package) => "{$what} is missing (package: {$package})", array_keys($this->missing($ctx)), $this->missing($ctx));
    }

    public function plan(Context $ctx): array
    {
        $packages = implode(' ', array_unique($this->missing($ctx)));
        if ($packages === '') {
            return [];
        }

        if ($ctx->isMac()) {
            return $this->has('brew') ? [Action::command('Install with Homebrew', "brew install {$packages}")] : [];
        }

        return $this->has('apt-get') ? [Action::command(
            'Install with apt',
            "sudo apt-get update -qq && sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {$packages} > /dev/null",
        )] : [];
    }

    public function manual(Context $ctx): string
    {
        return 'Install these with your package manager: '.implode(', ', array_unique($this->missing($ctx)));
    }

    /**
     * @return array<string, string> what's missing => the package that provides it
     */
    protected function missing(Context $ctx): array
    {
        $binaries = $ctx->isMac()
            ? ['wg' => 'wireguard-tools', 'wg-quick' => 'wireguard-tools', 'wireguard-go' => 'wireguard-go', 'git' => 'git', 'composer' => 'composer']
            : ['wg' => 'wireguard-tools', 'wg-quick' => 'wireguard-tools', 'nft' => 'nftables', 'curl' => 'curl', 'git' => 'git', 'composer' => 'composer'];

        $missing = [];
        foreach ($binaries as $binary => $package) {
            if (! $this->has($binary)) {
                $missing[$binary] = $package;
            }
        }

        // wg-quick needs bash 4+, which macOS doesn't ship
        if ($ctx->isMac() && ! $this->has('/opt/homebrew/bin/bash') && ! $this->has('/usr/local/bin/bash')) {
            $missing['bash 4+'] = 'bash';
        }

        $extensions = $ctx->isMac()
            ? ['sodium' => 'php', 'mbstring' => 'php', 'dom' => 'php']
            : ['sodium' => 'php-common', 'mbstring' => 'php-mbstring', 'dom' => 'php-xml'];
        foreach ($extensions as $extension => $package) {
            if (! extension_loaded($extension)) {
                $missing["PHP extension {$extension}"] = $package;
            }
        }

        return $missing;
    }
}
