<?php

use App\Exceptions\SystemException;
use App\Validation\WireGuardValidator;
use Tests\Support\Rig;

/*
 * A link's destinations (the only networks traffic out of its tunnel is forwarded and NATed to):
 * the service against a simulated Linux and macOS host. What the rules are is the root helper's
 * (HelperTest).
 */

afterEach(fn () => Rig::cleanup());

it('keeps a link\'s destinations with it, and its rules in line with them', function (string $os) {
    $rig = new Rig($os);

    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, nat: true, destinations: '10.20.0.5/16 ,192.0.2.50,  2001:db8:a::/48');

    // As the firewall lists them: networks, each with its mask
    expect($link->destinations)->toBe('10.20.0.0/16, 192.0.2.50/32, 2001:db8:a::/48')
        ->and($link->toArray()['destinations'])->toBe('10.20.0.0/16, 192.0.2.50/32, 2001:db8:a::/48')
        ->and($link->firewall)->toBe('ok')
        ->and($rig->host->conf('wg0'))->toContain("# inbound = false\n# destinations = 10.20.0.0/16, 192.0.2.50/32, 2001:db8:a::/48\n# format = ")
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true, 'destinations' => '10.20.0.0/16, 192.0.2.50/32, 2001:db8:a::/48']);

    // Changed live, like forward and NAT: no restart
    $starts = count($rig->shell->callsTo('sudo -n :helper up :name'));
    expect($rig->wg->updateLink('wg0', ['destinations' => '10.30.0.0/16'])->destinations)->toBe('10.30.0.0/16')
        ->and($rig->host->firewall['wg0']['destinations'])->toBe('10.30.0.0/16')
        // Another setting leaves them alone, and so does a restart
        ->and($rig->wg->updateLink('wg0', ['dns' => '1.1.1.1'])->destinations)->toBe('10.30.0.0/16')
        ->and($rig->wg->updateLink('wg0', ['port' => 51999])->destinations)->toBe('10.30.0.0/16')
        ->and($rig->host->firewall['wg0']['destinations'])->toBe('10.30.0.0/16')
        ->and(count($rig->shell->callsTo('sudo -n :helper up :name')))->toBe($starts + 1)
        ->and($rig->host->interfaceOf('wg0'))->not->toBeNull();

    // null (or ''): anywhere again
    expect($rig->wg->updateLink('wg0', ['destinations' => null])->destinations)->toBeNull()
        ->and($rig->host->conf('wg0'))->not->toContain('destinations')
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => true, 'nat' => true])
        ->and($rig->wg->updateLink('wg0', ['destinations' => '10.30.0.0/16'])->destinations)->toBe('10.30.0.0/16')
        ->and($rig->wg->updateLink('wg0', ['destinations' => ''])->destinations)->toBeNull();
})->with('os');

it('holds a link to its destinations with or without forward and NAT', function (string $os) {
    $rig = new Rig($os);

    // Neither forward nor NAT: peers still must not get anywhere else through this server
    $link = $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, destinations: '10.20.0.0/16');

    expect($link->forward)->toBeFalse()->and($link->nat)->toBeFalse()
        ->and($link->firewall)->toBe('ok')
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => false, 'nat' => false, 'destinations' => '10.20.0.0/16'])
        // Its rules come and go with the link, so its config has the helper's hooks
        ->and($rig->host->conf('wg0'))->toContain('PostUp = ', ' firewall-up ', ' firewall-down ');

    $rig->wg->updateLink('wg0', ['up' => false]);
    expect($rig->host->firewall)->toBe([]);
    $rig->wg->updateLink('wg0', ['up' => true]);
    expect($rig->host->firewall['wg0']['destinations'])->toBe('10.20.0.0/16');

    // Taken away: no rules left, and none to report on
    expect($rig->wg->updateLink('wg0', ['destinations' => null])->firewall)->toBeNull()
        ->and($rig->host->firewall)->toBe([])
        ->and($rig->host->conf('wg0'))->not->toContain('PostUp');
})->with('os');

it('notices when the rules of a link with destinations are gone or are others, and puts them back', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, destinations: '10.20.0.0/16');

    unset($rig->host->firewall['wg0']); // a ruleset reload that flushed everything
    expect($rig->wg->getLink('wg0')->firewall)->toBe('missing')
        ->and($rig->wg->repairLink('wg0')->firewall)->toBe('ok');

    // Rules for other destinations than the config asks for are not its rules
    $rig->host->firewall['wg0']['destinations'] = '10.20.0.0/16, 0.0.0.0/1';
    expect($rig->wg->getLink('wg0')->firewall)->toBe('missing')
        ->and($rig->wg->repairLink('wg0')->firewall)->toBe('ok')
        ->and($rig->host->firewall['wg0'])->toBe(['forward' => false, 'nat' => false, 'destinations' => '10.20.0.0/16']);
})->with('os');

it('undoes new destinations the host does not take', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, forward: true, destinations: '10.20.0.0/16');
    $conf = $rig->host->conf('wg0');
    $rig->shell->failOnce('sudo -n :helper firewall-up :link :iface', message: 'nft: syntax error');

    expect(fn () => $rig->wg->updateLink('wg0', ['destinations' => '10.30.0.0/16']))->toThrow(SystemException::class, 'could not be applied and was undone: nft: syntax error')
        ->and($rig->host->conf('wg0'))->toBe($conf)
        ->and($rig->host->firewall['wg0']['destinations'])->toBe('10.20.0.0/16');
});

it('refuses destinations that are none', function (string $destinations, string $error) {
    $rig = new Rig('linux');

    expect(fn () => $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, destinations: $destinations))->toThrow(InvalidArgumentException::class, $error)
        ->and($rig->host->files())->toBe([]);
})->with([
    'a name' => ['pbx.example.com', 'Invalid allowed IP or CIDR: pbx.example.com'],
    'a mask too long' => ['10.0.0.0/33', 'Invalid allowed IP or CIDR: 10.0.0.0/33'],
    'an empty entry' => ['10.20.0.0/16,', 'Empty entry in list'],
    'a line break' => ["10.20.0.0/16\nPostUp = id", 'Value must not contain control characters or line breaks.'],
    // "Everything" is what a link without destinations has: the two can't be told apart later
    'everything' => ['10.20.0.0/16, 0.0.0.0/0', '0.0.0.0/0 is every address'],
    'everything, in IPv6' => ['::/0', '::/0 is every address'],
    'an IPv4 network written as an IPv6 one' => ['::ffff:10.20.0.0/112', 'is an IPv4 address written as an IPv6 one'],
]);

it('writes destinations as networks, once each', function () {
    $validator = new WireGuardValidator;

    expect($validator->destinations('10.20.0.9/16, 10.20.0.0/16 ,192.0.2.50'))->toBe(['10.20.0.0/16', '192.0.2.50/32'])
        ->and($validator->destinations('2001:DB8:A:0::1/48,fd00::7'))->toBe(['2001:db8:a::/48', 'fd00::7/128'])
        ->and($validator->destinations('0.0.0.0/1'))->toBe(['0.0.0.0/1']);
});

it('keeps a link\'s destinations through a backup and its restore', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820, nat: true, destinations: '10.20.0.0/16, 2001:db8:a::/48');
    $backup = $rig->backup->create();
    $rig->wg->deleteLink('wg0');

    $rig->backup->restore($backup, ['wg0' => 'restore']);

    expect($rig->wg->getLink('wg0'))->destinations->toBe('10.20.0.0/16, 2001:db8:a::/48')->firewall->toBe('ok')
        ->and($rig->host->firewall['wg0']['destinations'])->toBe('10.20.0.0/16, 2001:db8:a::/48');

    // One with destinations nobody could have written is not restored
    $backup['links']['wg0']['conf'] = str_replace('# destinations = 10.20.0.0/16', '# destinations = everywhere', $backup['links']['wg0']['conf']);
    expect($rig->backup->problems($backup, 'wg0', ['wg0']))->toBe(['Invalid allowed IP or CIDR: everywhere']);
});
