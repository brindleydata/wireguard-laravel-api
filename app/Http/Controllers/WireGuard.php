<?php

namespace App\Http\Controllers;

use App\Services\Server;
use App\Services\WireGuard as WireGuardService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;

class WireGuard extends Controller
{
    public function __construct(
        protected WireGuardService $wg,
        protected Server $server,
    ) {}

    public function status(): array
    {
        return $this->server->status()->toArray();
    }

    public function ip(): array
    {
        return $this->server->ip();
    }

    public function links(): array
    {
        return $this->wg->listLinks();
    }

    public function link(string $name): array
    {
        $link = $this->wg->getLink($name);

        if ($link === null) {
            abort(404, "Link not found: {$name}");
        }

        return $link->toArray();
    }

    public function linkCreate(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => 'required|string|max:15',
            'ip' => 'required|string',
            'port' => 'nullable|integer|min:1|max:65535',
            'ifout' => 'nullable|string|max:15',
            'dns' => 'nullable|string',
            'keepalive' => 'nullable|integer|min:0|max:65535',
            'allowed_ips' => 'nullable|string',
            'forward' => 'nullable|boolean',
            'nat' => 'nullable|boolean',
            'up' => 'nullable|boolean',
        ]);

        $link = $this->wg->createLink(
            $data['name'],
            $data['ip'],
            $data['port'] ?? null,
            $data['ifout'] ?? null,
            $data['dns'] ?? null,
            $data['keepalive'] ?? null,
            $data['allowed_ips'] ?? null,
            $data['forward'] ?? false,
            $data['nat'] ?? false,
            $data['up'] ?? true,
        );

        return response()->json($link->toArray(), 201);
    }

    public function linkDelete(string $name): array
    {
        $this->wg->deleteLink($name);

        return ['message' => "Deleted link: {$name}"];
    }

    public function linkUpdate(Request $request, string $name): array
    {
        $data = $request->validate([
            'address' => 'nullable|string',
            'port' => 'nullable|integer|min:1|max:65535',
            'ifout' => 'nullable|string|max:15',
            'dns' => 'nullable|string',
            'keepalive' => 'nullable|integer|min:0|max:65535',
            'allowed_ips' => 'nullable|string',
            'forward' => 'nullable|boolean',
            'nat' => 'nullable|boolean',
            'up' => 'nullable|boolean',
        ]);

        // Filter out null values so only explicitly provided fields are passed
        $params = array_filter($data, fn ($v) => $v !== null);

        $link = $this->wg->updateLink($name, $params);

        return $link->toArray();
    }

    public function peers(string $link): array
    {
        $info = $this->wg->getLink($link);

        if ($info === null) {
            abort(404, "Link not found: {$link}");
        }

        return array_map(fn ($p) => $p->toArray(), $info->peers);
    }

    public function peerCreate(Request $request, string $link): JsonResponse
    {
        $data = $request->validate([
            'ip' => 'nullable|string',
        ]);

        $peer = $this->wg->addPeer($link, $data['ip'] ?? null);

        return response()->json($peer->toArray(), 201);
    }

    public function peerDelete(string $link, string $pubkey): array
    {
        $decoded = WireGuardService::safeToPubkey($pubkey);
        $this->wg->removePeer($link, $decoded);

        return ['message' => "Removed peer from {$link}"];
    }

    public function peerUpdate(Request $request, string $link, string $pubkey): array
    {
        $data = $request->validate([
            'allowed_ips' => 'nullable|string',
            'dns' => 'nullable|string',
        ]);

        $params = array_filter($data, fn ($v) => $v !== null);
        $decoded = WireGuardService::safeToPubkey($pubkey);

        $peer = $this->wg->updatePeer($link, $decoded, $params);

        return $peer->toArray();
    }

    public function peerConfig(string $link, string $pubkey): array
    {
        $decoded = WireGuardService::safeToPubkey($pubkey);
        $config = $this->wg->getPeerConfig($link, $decoded);

        if ($config === null) {
            abort(404, "Configuration not found for peer on {$link}");
        }

        return ['config' => $config];
    }
}
