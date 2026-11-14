<?php

namespace App\Http\Controllers;

use App\Services\QrCode;
use App\Services\Server;
use App\Services\WireGuard as WireGuardService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;

class WireGuard extends Controller
{
    public function __construct(
        protected WireGuardService $wg,
        protected Server $server,
    ) {}

    /** 200 or 503, nothing else: it's public. */
    public function health(): JsonResponse
    {
        $healthy = $this->server->healthy();

        return response()->json(['status' => $healthy ? 'ok' : 'unavailable'], $healthy ? 200 : 503);
    }

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
            'address6' => 'nullable|string',  // IPv6 address and prefix, or "auto"
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
            $data['address6'] ?? null,
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
            'address6' => 'nullable|string',  // IPv6 address and prefix, or "auto"; null removes it
            'port' => 'nullable|integer|min:1|max:65535',
            'ifout' => 'nullable|string|max:15',
            'dns' => 'nullable|string',                         // the link's client defaults:
            'keepalive' => 'nullable|integer|min:0|max:65535',  // null goes back to the global one
            'allowed_ips' => 'nullable|string',
            'forward' => 'nullable|boolean',
            'nat' => 'nullable|boolean',
            'up' => 'nullable|boolean',
        ]);

        // Only the fields that were sent. For most a null says nothing; for these it is a value:
        // no IPv6 address, or the global default instead of the link's own
        $params = array_filter($data, fn ($v) => $v !== null);
        foreach (['address6', 'dns', 'keepalive', 'allowed_ips'] as $field) {
            if ($request->exists($field)) {
                $params[$field] = $data[$field] ?? null;
            }
        }

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
            'name' => 'nullable|string',      // a label
            'networks' => 'nullable|string',  // networks behind the peer (site-to-site)
        ]);

        $peer = $this->wg->addPeer($link, $data['ip'] ?? null, $data['name'] ?? null, $data['networks'] ?? null);

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
            'ip' => 'nullable|string',          // tunnel address (server AllowedIPs + client Address)
            'dns' => 'nullable|string',         // client config DNS; null: the link's default
            'allowed_ips' => 'nullable|string', // client config AllowedIPs (routes); null: the link's default
            'name' => 'nullable|string',        // a label; null removes it
            'enabled' => 'nullable|boolean',    // false takes the peer off the interface
            'networks' => 'nullable|string',    // networks behind the peer; null removes them
        ]);

        $params = array_filter($data, fn ($v) => $v !== null);
        foreach (['name', 'networks', 'dns', 'allowed_ips'] as $field) {
            if ($request->exists($field)) {
                $params[$field] = $data[$field] ?? null;
            }
        }
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

    /** The client config as a QR code (SVG) for the WireGuard apps. It holds the private key. */
    public function peerQr(QrCode $qr, string $link, string $pubkey): Response
    {
        $config = $this->wg->getPeerConfig($link, WireGuardService::safeToPubkey($pubkey));

        if ($config === null) {
            abort(404, "Configuration not found for peer on {$link}");
        }

        return response($qr->svg($config), 200, ['Content-Type' => 'image/svg+xml', 'Cache-Control' => 'no-store']);
    }
}
