<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use Illuminate\Support\Facades\Artisan;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function index()
    {
        $out = null;
        $ret = Artisan::call('wg:list', [], $out);
        var_dump($ret, $out);
    }

    public function getInterface(string $link)
    {
        return "Getting ".$link;
    }

    public function storeInterface(string $link)
    {
        return "Storing ".$link;
    }

    public function destroyInterface(string $link)
    {
        return "Destroying ".$link;
    }

    public function getClient(string $link, string $client)
    {
        return "Getting ".$client." on ".$link;
    }

    public function storeClient(string $link, string $client)
    {
        return "Storing ".$client." on ".$link;
    }

    public function destroyClient(string $link, string $client)
    {
        return "Destroying ".$client." on ".$link;
    }
}
