<?php

namespace App\Http\Controllers;

use App\Services\QrCode;
use App\Services\Server;
use App\Services\WireGuard as WireGuardService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Routing\Controller;
use InvalidArgumentException;

class WireGuard extends Controller
{
    public function __construct(
        protected WireGuardService $wg,
        protected Server $server,
    ) {}

    /**
     * 200 or 503, and which app answers: it's public, so nothing else. The `app` lets a client
     * make sure the URL is one of these servers before it sends its API key there.
     */
    public function health(): JsonResponse
    {
        $healthy = $this->server->healthy();

        return response()->json(['status' => $healthy ? 'ok' : 'unavailable', 'app' => Server::APP], $healthy ? 200 : 503);
    }

    public function status(): array
    {
        return $this->server->status()->toArray();
    }

    public function ip(): array
    {
        return $this->server->ip();
    }

    /** The host's network interfaces (for a link's `ifout`), and the default one. */
    public function interfaces(): array
    {
        return $this->server->interfaces();
    }

    /**
     * A request's fields, checked against $rules. A field no rule knows is refused, not dropped:
     * a misspelled one would otherwise look like a change that was made.
     */
    protected function fields(Request $request, array $rules): array
    {
        $unknown = array_diff(array_map('strval', array_keys($request->all())), array_keys($rules));
        if ($unknown !== []) {
            throw new InvalidArgumentException((count($unknown) === 1 ? 'Unknown field: ' : 'Unknown fields: ').implode(', ', $unknown).'. Known: '.implode(', ', array_keys($rules)).'.');
        }

        return $request->validate($rules);
    }

    /**
     * A link's `destinations` as the service takes them: the comma-separated list the API's other
     * lists are, which is also what it answers with. A JSON array of networks is taken too. An
     * empty one is refused: it could mean nowhere as well as anywhere, and null says anywhere.
     */
    protected function destinations(mixed $value): ?string
    {
        if ($value === null || is_string($value)) {
            return $value;
        }
        if (! is_array($value) || $value === [] || ! array_is_list($value) || array_filter($value, fn (mixed $entry) => ! is_string($entry)) !== []) {
            throw new InvalidArgumentException('destinations must be networks, as a comma-separated list or an array of them (e.g. ["10.1.0.0/16", "2001:db8::/32"]). For anywhere, send null.');
        }

        return implode(', ', $value);
    }

    public function links(): array
    {
        return $this->wg->listLinks();
    }

    public function link(string $name): array
    {
        return $this->wg->linkOrFail($name)->toArray();
    }

    public function linkCreate(Request $request): JsonResponse
    {
        $data = $this->fields($request, [
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
            'mtu' => 'nullable|integer|min:576|max:65535',  // for the interface and its clients
            'inbound' => 'nullable|boolean',              // forwarding into the tunnel: connections that start outside too
            'allow_default_route' => 'nullable|boolean',  // peers may route a default route (where the server allows it)
            'allow_own_networks' => 'nullable|boolean',   // peers may route the server's own networks (likewise)
            'endpoint' => 'nullable|string',      // where its clients connect, host or host:port (else detected now, and kept)
            'private_key' => 'nullable|string',   // its own key, to move a link here (else a new one)
            'destinations' => 'nullable',         // the only networks out of its tunnel, "a, b" or an array (else anywhere)
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
            $data['mtu'] ?? null,
            (bool) ($data['inbound'] ?? false),
            (bool) ($data['allow_default_route'] ?? false),
            (bool) ($data['allow_own_networks'] ?? false),
            $data['endpoint'] ?? null,
            $data['private_key'] ?? null,
            $this->destinations($data['destinations'] ?? null),
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
        $data = $this->fields($request, [
            'address' => 'nullable|string',
            'address6' => 'nullable|string',  // IPv6 address and prefix, or "auto" (kept if it has one); null removes it
            'port' => 'nullable|integer|min:1|max:65535',
            'ifout' => 'nullable|string|max:15',
            'dns' => 'nullable|string',                         // the link's client defaults:
            'keepalive' => 'nullable|integer|min:0|max:65535',  // null goes back to the fixed default
            'allowed_ips' => 'nullable|string',
            'forward' => 'nullable|boolean',
            'nat' => 'nullable|boolean',
            'up' => 'nullable|boolean',
            'move_peers' => 'nullable|boolean',  // with a new address: peers keep their host number in it
            'mtu' => 'nullable|integer|min:576|max:65535',  // null: wg-quick's own again
            'inbound' => 'nullable|boolean',
            'allow_default_route' => 'nullable|boolean',
            'allow_own_networks' => 'nullable|boolean',
            'endpoint' => 'nullable|string',  // null: detected anew
            'destinations' => 'nullable',     // "a, b" or an array; null: anywhere again
        ]);

        $link = $this->wg->updateLink($name, $this->linkParams($request, $data, ['address6', 'dns', 'keepalive', 'allowed_ips', 'mtu', 'endpoint', 'destinations']));

        return $link->toArray();
    }

    /**
     * A link's settings as the service takes them: only the fields that were sent. For most a
     * null says nothing; for $nullable ones it is a value: no IPv6 address, anywhere instead of
     * destinations, or the default instead of the link's own.
     */
    protected function linkParams(Request $request, array $data, array $nullable): array
    {
        if (array_key_exists('destinations', $data)) {
            $data['destinations'] = $this->destinations($data['destinations']);
        }

        $params = array_filter($data, fn ($v) => $v !== null);
        foreach ($nullable as $field) {
            if ($request->exists($field)) {
                $params[$field] = $data[$field] ?? null;
            }
        }

        return $params;
    }

    /**
     * Take a config the app didn't write (by hand, or by the API before this one) under its
     * management, with these settings. Answers with the link as GET /link/{name} does, and under
     * `adoption` what was kept, dropped and applied, and whose private keys are here. With
     * `dry_run` it only says what it would do, and changes nothing.
     */
    public function linkAdopt(Request $request, string $name): array
    {
        $data = $this->fields($request, [
            'ifout' => 'nullable|string|max:15',
            'forward' => 'nullable|boolean',
            'nat' => 'nullable|boolean',
            'inbound' => 'nullable|boolean',
            'destinations' => 'nullable',
            'allowed_ips' => 'nullable|string',
            'dns' => 'nullable|string',
            'keepalive' => 'nullable|integer|min:0|max:65535',
            'mtu' => 'nullable|integer|min:576|max:65535',
            'endpoint' => 'nullable|string',
            'allow_default_route' => 'nullable|boolean',
            'allow_own_networks' => 'nullable|boolean',
            'dry_run' => 'nullable|boolean',
        ]);
        $dry_run = (bool) ($data['dry_run'] ?? false);
        unset($data['dry_run']);

        $result = $this->wg->adoptLink($name, $this->linkParams($request, $data, ['dns', 'keepalive', 'allowed_ips', 'mtu', 'endpoint', 'destinations']), $dry_run);

        return [...$result['link']->toArray(), 'adoption' => $result['adoption']];
    }

    /** New keys for a link (its own key pair). Every client needs its new config: the link's public key is in it. */
    public function linkRekey(string $name): array
    {
        return $this->wg->rekeyLink($name)->toArray();
    }

    /** Put a running link's forward/NAT rules back, when another tool took them away. */
    public function linkRepair(string $name): array
    {
        return $this->wg->repairLink($name)->toArray();
    }

    public function peers(string $link): array
    {
        return array_map(fn ($p) => $p->toArray(), $this->wg->linkOrFail($link)->peers);
    }

    /** 404 says which isn't there: the link (`link_not_found`) or the peer (`peer_not_found`). */
    public function peer(string $link, string $pubkey): array
    {
        return $this->wg->peerOrFail($link, $pubkey)->toArray();
    }

    public function peerCreate(Request $request, string $link): JsonResponse
    {
        $data = $this->fields($request, [
            'ip' => 'nullable|string',
            'name' => 'nullable|string',      // a label
            'networks' => 'nullable|string',  // networks behind the peer (site-to-site)
            'remote' => 'nullable|string',    // host:port the server connects to (else the peer connects)
            'public_key' => 'nullable|string',     // its own key pair's (then no private key is stored here)
            'preshared_key' => 'nullable|string',  // else a new one
            'dns' => 'nullable|string',            // its own client settings (else its link's)
            'keepalive' => 'nullable|integer|min:0|max:65535',
            'allowed_ips' => 'nullable|string',
            'enabled' => 'nullable|boolean',       // false: added disabled
        ]);

        $peer = $this->wg->addPeer($link, $data['ip'] ?? null, $data['name'] ?? null, $data['networks'] ?? null, $data['remote'] ?? null,
            $data['public_key'] ?? null, $data['preshared_key'] ?? null, $data['dns'] ?? null, $data['keepalive'] ?? null, $data['allowed_ips'] ?? null,
            (bool) ($data['enabled'] ?? true));

        return response()->json($peer->toArray(), 201);
    }

    public function peerDelete(string $link, string $pubkey): array
    {
        $this->wg->removePeer($link, $pubkey);

        return ['message' => "Removed peer from {$link}"];
    }

    public function peerUpdate(Request $request, string $link, string $pubkey): array
    {
        $data = $this->fields($request, [
            'ip' => 'nullable|string',          // tunnel address (server AllowedIPs + client Address)
            'dns' => 'nullable|string',         // client config DNS; null: the link's default
            'allowed_ips' => 'nullable|string', // client config AllowedIPs (routes); null: the link's default
            'keepalive' => 'nullable|integer|min:0|max:65535', // client config keepalive; null: the link's default
            'name' => 'nullable|string',        // a label; null removes it
            'enabled' => 'nullable|boolean',    // false takes the peer off the interface
            'networks' => 'nullable|string',    // networks behind the peer; null removes them
            'remote' => 'nullable|string',      // host:port the server connects to; null: the peer connects
        ]);

        $params = array_filter($data, fn ($v) => $v !== null);
        foreach (['name', 'networks', 'remote', 'dns', 'allowed_ips', 'keepalive'] as $field) {
            if ($request->exists($field)) {
                $params[$field] = $data[$field] ?? null;
            }
        }
        $peer = $this->wg->updatePeer($link, $pubkey, $params);

        return $peer->toArray();
    }

    /** New keys for a peer. Its public key changes: the answer has the new one, and the new client config. */
    public function peerRekey(string $link, string $pubkey): array
    {
        return $this->wg->rekeyPeer($link, $pubkey)->toArray();
    }

    public function peerConfig(string $link, string $pubkey): array
    {
        return ['config' => $this->wg->peerConfigOrFail($link, $pubkey)];
    }

    /** The client config as a QR code (SVG) for the WireGuard apps. It holds the private key. */
    public function peerQr(QrCode $qr, string $link, string $pubkey): Response
    {
        // The whole config, its private key included: a peer with a key of its own has none (422)
        $config = $this->wg->peerConfigOrFail($link, $pubkey, with_key: true);

        return response($qr->svg($config), 200, ['Content-Type' => 'image/svg+xml', 'Cache-Control' => 'no-store']);
    }
}
