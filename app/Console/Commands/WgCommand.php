<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgCommand extends Command
{
    protected $signature = 'wg:help {--os= : Target OS (linux or mac)} {--user= : Web server user (default: www-data on Linux, _www on macOS)}';

    protected $description = 'Show prerequisites';

    public function handle(WireGuard $wg): int
    {
        $os = $this->option('os') ?? (PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux');
        $mac = in_array($os, ['mac', 'macos', 'darwin'], true);
        $user = $this->option('user') ?? ($mac ? '_www' : 'www-data');

        $mac ? $this->macOS($user) : $this->linux($user);

        return Command::SUCCESS;
    }

    protected function linux(string $user): void
    {
        $this->info('Linux prerequisites:');
        $this->line('');

        $this->comment('1. Install wireguard-tools, nftables and PHP');
        $this->line('   sudo apt install wireguard-tools nftables curl php-cli php-mbstring php-xml php-curl');
        $this->line('');

        $this->comment('2. Enable IP forwarding (needed for forward/NAT)');
        $this->line('   echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wireguard.conf');
        $this->line('   sudo sysctl --system');
        $this->line('');

        $this->helperSteps(3, $user, 'root');
    }

    protected function macOS(string $user): void
    {
        $this->info('macOS prerequisites:');
        $this->line('');

        $this->comment('1. Install wireguard-tools, wireguard-go and bash 4+ (wg-quick needs it)');
        $this->line('   brew install wireguard-tools wireguard-go bash');
        $this->line('');

        $this->comment('2. Enable IP forwarding (needed for forward/NAT)');
        $this->line('   sudo sysctl -w net.inet.ip.forwarding=1');
        $this->line('');

        $this->comment('3. Add the pf anchors for forward/NAT rules (one-time)');
        $this->line(<<<'SNIPPET'
   sudo bash -c 'cat >> /etc/pf.conf <<EOF

   # WireGuard NAT anchors
   nat-anchor "wg/*"
   anchor "wg/*"
   EOF'
   sudo pfctl -f /etc/pf.conf
SNIPPET);
        $this->line('');

        $this->helperSteps(4, $user, 'wheel');
    }

    /**
     * The root helper is the only command the web server user may run as root.
     */
    protected function helperSteps(int $step, string $user, string $group): void
    {
        $helper = config('wireguard.helper');
        $source = base_path('bin/wgla-helper');

        $this->comment("{$step}. Install the root helper (again after every update of this app)");
        // mkdir -p leaves an existing directory's owner alone (Homebrew owns /usr/local/sbin on Intel Macs)
        $this->line('   sudo mkdir -p '.dirname($helper));
        $this->line("   sudo install -o root -g {$group} -m 755 {$source} {$helper}");
        $this->line('');

        $step++;
        $this->comment("{$step}. Let the web server user run it as root, and nothing else");
        $this->line("   echo '{$user} ALL=(root) NOPASSWD: {$helper}' | sudo tee /etc/sudoers.d/wgla > /dev/null");
        $this->line('   sudo chmod 440 /etc/sudoers.d/wgla');
        $this->line('   sudo visudo -cf /etc/sudoers.d/wgla');
        $this->line('');

        $step++;
        $this->comment("{$step}. Set API_KEY in .env (the API refuses every protected request without it)");
        $this->line('   echo "API_KEY=$(openssl rand -hex 32)" >> .env');
        $this->line('');
    }
}
