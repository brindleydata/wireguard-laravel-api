<?php

namespace App\Console\Commands;

use App\Services\WireGuard;
use Illuminate\Console\Command;

class WgCommand extends Command
{
    protected $signature = 'wg:help {--os= : Target OS (linux or mac)} {--arch= : Architecture (arm64 or x86_64, macOS only)}';

    protected $description = 'Show prerequisites';

    public function handle(WireGuard $wg): int
    {
        $os = $this->option('os') ?? (PHP_OS_FAMILY === 'Darwin' ? 'mac' : 'linux');

        if ($os === 'mac' || $os === 'macos' || $os === 'darwin') {
            $arch = $this->option('arch') ?? php_uname('m');
            $this->macOS($arch === 'arm64');
        } else {
            $this->linux();
        }

        return Command::SUCCESS;
    }

    protected function linux(): void
    {
        $this->info('Linux prerequisites:');
        $this->line('');

        $this->comment('1. Install wireguard-tools and PHP sodium extension');
        $this->line('   apt install wireguard-tools nftables curl php-sodium');
        $this->line('');

        $this->comment('2. Enable IP forwarding');
        $this->line('   sudo sysctl -w net.ipv4.ip_forward=1');
        $this->line('');
        $this->line('   To persist across reboots:');
        $this->line('   echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-wireguard.conf');
        $this->line('   sudo sysctl --system');
        $this->line('');

        $this->comment('3. Create sudoers file (replace www-data with your web server user)');
        $this->line(<<<'SNIPPET'
   sudo tee /etc/sudoers.d/wireguard > /dev/null <<'EOF'
   www-data ALL=(root) NOPASSWD: \
       /usr/bin/wg, \
       /usr/bin/wg-quick, \
       /usr/sbin/nft, \
       /bin/systemctl enable wg-quick@*, \
       /bin/systemctl disable wg-quick@*, \
       /bin/systemctl start wg-quick@*, \
       /bin/systemctl stop wg-quick@*, \
       /bin/cp, \
       /bin/rm, \
       /bin/cat, \
       /bin/chmod, \
       /bin/mkdir
   EOF
   sudo chmod 440 /etc/sudoers.d/wireguard
SNIPPET);
        $this->line('');

        $this->comment('4. Validate sudoers syntax');
        $this->line('   sudo visudo -cf /etc/sudoers.d/wireguard');
        $this->line('');
    }

    protected function macOS(bool $arm64): void
    {
        $prefix = $arm64 ? '/opt/homebrew' : '/usr/local';
        $arch = $arm64 ? 'arm64' : 'x86_64';

        $this->info("macOS prerequisites ({$arch}):");
        $this->line('');

        $this->comment('1. Install wireguard-tools, wireguard-go, bash 4+, and PHP sodium extension');
        $this->line('   brew install wireguard-tools wireguard-go bash php-sodium');
        $this->line('');

        $this->comment('2. Fix wg-quick shebang (macOS ships bash 3, wg-quick needs 4+)');
        $this->line("   sudo sed -i \"\" \"1s|.*|#\\!{$prefix}/bin/bash|\" {$prefix}/bin/wg-quick");
        $this->line('');

        $this->comment('3. Enable IP forwarding');
        $this->line('   sudo sysctl -w net.inet.ip.forwarding=1');
        $this->line('');

        $this->comment('4. Set up pfctl anchors for NAT');
        $this->line(<<<'SNIPPET'
   sudo bash -c 'cat >> /etc/pf.conf <<EOF

   # WireGuard NAT anchors
   nat-anchor "wg/*"
   anchor "wg/*"
   EOF'
   sudo pfctl -f /etc/pf.conf
SNIPPET);
        $this->line('');

        $this->comment('5. Create sudoers file (replace _www with your web server user)');
        $this->line(<<<SNIPPET
   sudo tee /etc/sudoers.d/wireguard > /dev/null <<'EOF'
   _www ALL=(root) NOPASSWD: \\
       {$prefix}/bin/wg, \\
       {$prefix}/bin/wg-quick, \\
       /usr/sbin/sysctl -w net.inet.ip.forwarding=*
   EOF
   sudo chmod 440 /etc/sudoers.d/wireguard
SNIPPET);
        $this->line('');

        $this->comment('6. Validate sudoers syntax');
        $this->line('   sudo visudo -cf /etc/sudoers.d/wireguard');
        $this->line('');
    }
}
