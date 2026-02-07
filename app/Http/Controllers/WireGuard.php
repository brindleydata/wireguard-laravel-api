<?php

namespace App\Http\Controllers;

use App\Services\WireGuard as WireGuardService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class WireGuard extends Controller
{
    public function __construct(
        protected WireGuardService $wg,
    ) {}

    public function status(): JsonResponse
    {
        try {
            return response()->json($this->wg->systemStatus()->toArray());
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function interfaces(): JsonResponse
    {
        try {
            return response()->json($this->wg->listInterfaces());
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function interface(string $name): JsonResponse
    {
        $interface = $this->wg->getInterface($name);
        if ($interface === null) {
            return response()->json(['error' => "Interface not found: {$name}"], 404);
        }

        return response()->json($interface->toArray());
    }

    public function interfaceAdd(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => 'required|string|max:15',
            'ip' => 'required|string',
            'port' => 'nullable|integer|min:1|max:65535',
            'ifout' => 'nullable|string|max:15',
            'dns' => 'nullable|string',
            'keepalive' => 'nullable|integer|min:0|max:65535',
            'allowed_ips' => 'nullable|string',
        ]);

        try {
            $interface = $this->wg->createInterface(
                $data['name'],
                $data['ip'],
                $data['port'] ?? null,
                $data['ifout'] ?? null,
                $data['dns'] ?? null,
                $data['keepalive'] ?? null,
                $data['allowed_ips'] ?? null,
            );

            return response()->json($interface->toArray(), 201);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function interfaceDelete(string $name): JsonResponse
    {
        try {
            $this->wg->deleteInterface($name);

            return response()->json(['message' => "Deleted interface: {$name}"]);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], 404);
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function peers(string $interface): JsonResponse
    {
        $info = $this->wg->getInterface($interface);
        if ($info === null) {
            return response()->json(['error' => "Interface not found: {$interface}"], 404);
        }

        return response()->json(
            array_map(fn ($p) => $p->toArray(), $info->peers)
        );
    }

    public function peerAdd(Request $request, string $interface): JsonResponse
    {
        $data = $request->validate([
            'ip' => 'required|string',
        ]);

        try {
            $peer = $this->wg->addPeer($interface, $data['ip']);

            return response()->json($peer->toArray(), 201);
        } catch (\InvalidArgumentException $e) {
            return response()->json(['error' => $e->getMessage()], 422);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], 404);
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function peerDelete(string $interface, string $peer): JsonResponse
    {
        try {
            $this->wg->removePeer($interface, $peer);

            return response()->json(['message' => "Removed peer {$peer} from {$interface}"]);
        } catch (\RuntimeException $e) {
            return response()->json(['error' => $e->getMessage()], 404);
        } catch (\Throwable $e) {
            return response()->json(['error' => $e->getMessage()], 500);
        }
    }

    public function peerConfig(string $interface, string $ip): JsonResponse
    {
        $config = $this->wg->getPeerConfig($interface, $ip);
        if ($config === null) {
            return response()->json(['error' => "Configuration not found for peer {$ip} on {$interface}"], 404);
        }

        return response()->json(['config' => $config]);
    }
}
