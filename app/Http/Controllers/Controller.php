<?php

namespace App\Http\Controllers;

use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use App\WireGuard\Service as WireGuard;

class Controller extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    protected $wg;

    public function __construct(WireGuard $wg)
    {
        $this->wg = $wg;
    }

    public function index()
    {
        return $this->wg->getInterfaces();
    }

    public function getInterface(string $link)
    {
        $iface = $this->wg->getInterface($link);
        return response()->json($iface);
    }

    public function storeInterface(string $link, string $ip)
    {
        if (!$ip) {
            throw new \InvalidArgumentException("'vpn_address' field is required.");
        }

        $ifout = request()->post('ifout', 'eth0');
        $port = request()->post('port', mt_rand(33000, 65000));

        $ret = $this->wg->storeInterface($link, $ip, $ifout, $port);
        return response()->json($ret);
    }

    public function destroyInterface(string $link)
    {
        $ret = $this->wg->destroyInterface($link);
        return response()->json($ret);
    }

    public function getClient(string $link, string $client)
    {
        $ret = $this->wg->getPeer($link, $client);
        return response()->json($ret);
    }

    public function storeClient(string $link, string $client)
    {
        $ret = $this->wg->storePeer($link, $client);
        return response()->json($ret);
    }

    public function destroyClient(string $link, string $client)
    {
        $ret = $this->wg->destroyPeer($link, $client);
        return response()->json($ret);
    }

    public function genPubKey($priv = null)
    {
        if (!$priv) {
            $priv = request()->post('priv');
        }

        $ret = $this->wg->genPubKey($priv);
        return response()->json($ret);
    }
}
