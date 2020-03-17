<?php

namespace App\Console\Commands;

class WgDelete extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:delete {link}';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'Delete Wireguard interface';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $link = $this->argument('link');
        if (!$this->verifyInterface($link)) {
            $this->error("Interface do not exists: {$link}");
            die();
        }

        $this->system("systemctl stop wg-quick@{$link}", "Could not stop {$link}");
        $this->system("systemctl disable wg-quick@{$link}", "Could not disable {$link}");
    }
}
