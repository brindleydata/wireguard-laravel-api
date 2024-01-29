<?php

namespace App\Http\Controllers;

use App\Models\Link;
use App\Models\Peer;
use App\Services\WireGuard as WireGuardService;
use Illuminate\Foundation\Auth\Access\AuthorizesRequests;
use Illuminate\Foundation\Bus\DispatchesJobs;
use Illuminate\Foundation\Validation\ValidatesRequests;
use Illuminate\Http\JsonResponse;
use Illuminate\Routing\Controller;
use Exception;

class WireGuard extends Controller
{
    use AuthorizesRequests, DispatchesJobs, ValidatesRequests;

    public function __construct(
        protected WireGuardService $wg) {
    }

    public function status(): JsonResponse
    {
        return response()->json($this->wg->status());
    }

    public function links(): JsonResponse
    {
        return response()->json(
            $this->wg->links());
    }

    public function link(string $name): JsonResponse {
        return response()->json($this->wg->link($name));
    }

    public function link_add(): JsonResponse
    {
        // @todo: validate
        $data = request()->all();
        return response()->json($this->wg->link_add($data));
    }

    public function link_rm(string $name): JsonResponse
    {
        return response()->json($this->wg->link_rm($name));
    }

    public function peer_add(string $link): JsonResponse
    {
        // @todo: validate
        $data = request()->all();
        return response()->json($this->wg->peer_add($link, $data));
    }

    public function peer_rm(string $link, string $peer): JsonResponse
    {
        return response()->json($this->wg->peer_rm($link, $peer));
    }
}
