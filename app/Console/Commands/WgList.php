<?php

namespace App\Console\Commands;

class WgList extends WgCommand
{
    /**
     * The name and signature of the console command.
     * @var string
     */
    protected $signature = 'wg:list';

    /**
     * The console command description.
     * @var string
     */
    protected $description = 'List available Wireguard interfaces';

    /**
     * Execute the console command.
     * @return mixed
     */
    public function handle()
    {
        $interfaces = $this->system('wg show interfaces', 'Can not retreive Wireguard interfaces list.', true);
        $this->info('Available Wireguard interfaces:');
        $this->line($interfaces);
    }
}
