<?php

namespace App\Http\Controllers;

use App\WireGuard\Adapter;
use App\WireGuard\Exception;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller as BaseController;
use App\WireGuard\Service as WireGuard;
use App\WireGuard\Peer;

class WireGuardController extends BaseController
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    /**
     * @var WireGuard
     */
    protected $wg;

    /**
     * WireGuardController constructor.
     * @param WireGuard $wg
     */
    public function __construct(WireGuard $wg)
    {
        $this->wg = $wg;
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getStatus()
    {
        return $this->wg->getStatus();
    }

    /**
     * @return array
     * @throws Exception
     */
    public function getInterfaces()
    {
        return $this->wg->getInterfaces();
    }

    /**
     * @param string $name
     * @return JsonResponse
     * @throws Exception
     */
    public function getInterface(string $name)
    {
        $interface = Adapter::Read($name);
        return response()->json($interface);
    }

    /**
     * @return JsonResponse
     * @throws Exception
     */
    public function storeInterface()
    {
        $data = request()->all();
        $interface = Adapter::Create($data);
        $interface->save();
        return response()->json($interface);
    }

    /**
     * @param string $name
     * @return JsonResponse
     * @throws Exception
     */
    public function destroyInterface(string $name)
    {
        $interface = Adapter::Read($name);
        $ret = $interface->delete();
        return response()->json($ret);
    }

    /**
     * @param string $interface
     * @return JsonResponse
     * @throws Exception
     */
    public function getClients(string $interface)
    {
        $interface = Adapter::Read($interface);
        $clients = Peer::ReadAll($interface);
        return response()->json($clients);
    }

    /**
     * @param string $interface
     * @return JsonResponse
     * @throws Exception
     */
    public function storeClient(string $interface)
    {
        $interface = Adapter::Read($interface);

        $data = request()->all();
        $peer = Peer::Create($interface, $data);
        $peer->save();

        return response()->json($peer);
    }

    /**
     * @param string $interface
     * @param string $name
     * @return JsonResponse
     * @throws Exception
     */
    public function destroyClient(string $interface, string $name)
    {
        $interface = Adapter::Read($interface);
        $peer = Peer::Read($interface, $name);
        $ret = $peer->delete();

        return response()->json($ret);
    }
}
