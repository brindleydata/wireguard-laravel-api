<?php

namespace App\Services;

use App\Models\Link;

class WireGuard
{
    public function __construct(
        protected array $config = [],
        protected Host $host,
    ) {
    }

    public function status(): array
    {
        return $this->host->status();
    }

    public function genkey(): string
    {
        return $this->host->cmd('wg genkey');
    }

    public function genpsk(): string
    {
        return $this->host->cmd('wg genpsk');
    }

    public function pubkey(string $privkey): string
    {
        $privkey = escapeshellarg($privkey);
        return $this->host->cmd("echo {$privkey} | wg pubkey");
    }

    public function links(): array
    {
        $links = explode(' ', $this->host->cmd('wg show interfaces'));
        foreach ($links as &$link)
            $link = trim($link);

        return $links;
    }

    public function link(string $name): ?Link
    {
        if (!in_array($name, $this->links()))
            return null;

        $peers = [];
        $ip = $this->host->ip($name);
        $info = $this->host->cmd("sudo wg show {$name} dump");
        [$privkey, $pubkey, $port] = explode("\t", $info);

        return compact('name', 'privkey', 'pubkey', 'port');

        /*
        $name = escapeshellarg($name);
        $info = $this->host->cmd("ip addr show dev {$name}");
        if (empty($info[2]))
            return null;

        preg_match('/inet (?<ip>\d+.\d+.\d+.\d+/\d+)/', $info[2], $matches);
        if (empty($matches['ip']))
            return null;

        $ip = $matches['ip'];

        $link = new Link(wg: $this);
        $link->ip = $ip;
        return $link;
        */
    }

    public function link_add(array $info): bool
    {
        return false;
    }

    public function link_rm(string $name): bool
    {
        return false;
    }

    public function peer_add(string $link, array $data): bool
    {
        return false;
    }

    public function peer_rm(string $link, string $peer): bool
    {
        return false;
    }
}
