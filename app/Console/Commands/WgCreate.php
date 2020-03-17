<?php

namespace App\Console\Commands;

class WgCreate extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:create {link} {ip} {port?} {ifout?}';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Create Wireguard link.';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $link = $this->argument('link');
        if ($this->verifyInterface($link)) {
            $this->error("Interface exists: {$link}");
            die(1);
        }

        $ip = $this->argument('ip');
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $this->error("Invalid IP address.");
            die(1);
        }

        $ifout = $this->argument('ifout');
        if (empty($ifout)) {
            $ifout = 'eth0';
        }

        $port = $this->argument('port');
        if (empty($port)) {
            $port = mt_rand(33000, 65000);
        }

        $privkey = $this->genPrivKey();
        $pubkey = $this->genPubKey($privkey);

        $template = <<<EOF
        [Interface]
        Address    = {$ip}/32
        SaveConfig = true
        PrivateKey = {$privkey}
        ListenPort = {$port}
        PostUp     = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -o {$ifout} -j MASQUERADE;
        PostDown   = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -o {$ifout} -j MASQUERADE;
        EOF;

        @unlink("/etc/wireguard/{$link}.conf");

        $ret = $this->system("echo '{$template}\n\n' > /etc/wireguard/{$link}.conf", "Could not write /etc/wireguard/{$link}.conf");
        if ($ret === false) {
            $this->error("Add these lines into /etc/wireguard/{$link}.conf manually");
            $this->line("");
            $this->info($template);
            $this->line("");
            $this->warn("And execute following commands:");
            $this->line("");
            $this->line("systemctl enable wg-quick@{$link}");
            $this->line("systemctl start wg-quick@{$link}");
            die();
        }

        $this->system("systemctl enable wg-quick@{$link}", "Could not enable {$link}");
        $this->system("systemctl start wg-quick@{$link}", "Could not start {$link}");
    }
}
