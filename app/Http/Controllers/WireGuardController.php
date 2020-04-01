<?php

namespace App\Http\Controllers;

use App\WireGuard\Adapter;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Routing\Controller as BaseController;
use App\WireGuard\Service as WireGuard;
use InvalidArgumentException;

class WireGuardController extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    protected $wg;

    public function __construct(WireGuard $wg)
    {
        $this->wg = $wg;
    }

    public function getStatus()
    {
        return $this->wg->getStatus();
    }

    public function getInterfaces()
    {
        return $this->wg->getInterfaces();
    }

    public function getInterface(string $name)
    {
        $interface = Adapter::Read($name);
        return response()->json($interface);
    }

    public function storeInterface()
    {
        $data = request()->all();
        $interface = Adapter::Create($data);
        $interface->save();
        return response()->json($interface);
    }

    public function destroyInterface(string $name)
    {
        $interface = Adapter::Read($name);
        $ret = $interface->delete();
        return response()->json($ret);
    }

    /*
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
    */
}
