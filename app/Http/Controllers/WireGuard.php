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
        ]);

        $link = $this->wg->createLink(
            $data['name'],
            $data['ip'],
            $data['port'] ?? null,
            $data['ifout'] ?? null,
            $data['dns'] ?? null,
            $data['keepalive'] ?? null,
            $data['allowed_ips'] ?? null,
        );

        return response()->json($link->toArray(), 201);
    }

    public function linkDelete(string $name): array
    {
        $this->wg->deleteLink($name);

        return ['message' => "Deleted link: {$name}"];
    }

    public function linkUp(string $name): array
    {
        $this->wg->linkUp($name);

        return ['message' => "Link is up: {$name}"];
    }

    public function linkDown(string $name): array
    {
        $this->wg->linkDown($name);

        return ['message' => "Link is down: {$name}"];
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
            'ip' => 'required|string',
        ]);

        $peer = $this->wg->addPeer($link, $data['ip']);

        return response()->json($peer->toArray(), 201);
    }

    public function peerDelete(string $link, string $ip): array
    {
        $this->wg->removePeer($link, $ip);

        return ['message' => "Removed peer {$ip} from {$link}"];
    }

    public function peerConfig(string $link, string $ip): array
    {
        $config = $this->wg->getPeerConfig($link, $ip);

        if ($config === null) {
            abort(404, "Configuration not found for peer {$ip} on {$link}");
        }

        return ['config' => $config];
    }
}
