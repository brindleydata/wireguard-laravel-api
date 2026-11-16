<?php

use App\Exceptions\CommandFailedException;
use App\Exceptions\ConflictException;
use App\Exceptions\ErrorCode;
use App\Exceptions\HelperException;
use App\Exceptions\NotFoundException;
use App\Exceptions\SystemException;
use App\Services\KeyManager;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\Exception\NotFoundHttpException;
use Tests\Fakes\CommandFailed;
use Tests\Support\Rig;

/*
 * What a client of the API tells errors apart by: the code of each kind of failure, and that the
 * service says the right one (a link or a peer that isn't there is never a mistake in the request
 * or a host that failed, nor the other way round).
 */

afterEach(fn () => Rig::cleanup());

it('has a code for every kind of failure', function (Throwable $e, string $code) {
    expect(ErrorCode::of($e))->toBe($code);
})->with([
    'a link that is not there' => [NotFoundException::link('wg0'), 'link_not_found'],
    'a peer that is not there' => [NotFoundException::peer('key'), 'peer_not_found'],
    'a route that is not there' => [new NotFoundHttpException, 'route_not_found'],
    'a method a route does not take' => [new HttpException(405), 'method_not_allowed'],
    'a clash' => [new ConflictException('Port taken'), 'conflict'],
    'a config the app does not manage' => [new ConflictException('', ErrorCode::UNMANAGED_CONFIG), 'unmanaged_config'],
    'a value that is none' => [new InvalidArgumentException('Invalid port'), 'invalid_input'],
    'no API key' => [new HttpException(403), 'unauthorized'],
    'too many requests' => [new HttpException(429), 'rate_limited'],
    'a command that failed' => [new CommandFailed('exit 1'), 'system_error'],
    'a helper that is not installed' => [new HelperException('missing'), 'system_error'],
    'a bug' => [new LogicException('oops'), 'system_error'],
    'the framework failing' => [new HttpException(503), 'system_error'],
    'another refusal of the framework\'s' => [new HttpException(413), 'request_refused'],
]);

it('says which is not there, the link or the peer', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $nobody = (new KeyManager)->pubkey((new KeyManager)->genkey());
    $code = function (Closure $ask) {
        try {
            $ask();
        } catch (NotFoundException $e) {
            return $e->errorCode;
        }

        return null;
    };

    expect($code(fn () => $rig->wg->linkOrFail('wg9')))->toBe('link_not_found')
        ->and($code(fn () => $rig->wg->peerOrFail('wg9', $peer->public_key)))->toBe('link_not_found')
        ->and($code(fn () => $rig->wg->peerOrFail('wg0', $nobody)))->toBe('peer_not_found')
        ->and($code(fn () => $rig->wg->peerOrFail('wg0', 'not-a-key')))->toBe('peer_not_found')
        ->and($code(fn () => $rig->wg->peerConfigOrFail('wg0', $nobody)))->toBe('peer_not_found')
        ->and($code(fn () => $rig->wg->updatePeer('wg0', $nobody, ['name' => 'x'])))->toBe('peer_not_found')
        ->and($code(fn () => $rig->wg->removePeer('wg9', $nobody)))->toBe('link_not_found')
        ->and($code(fn () => $rig->wg->rekeyPeer('wg0', $nobody)))->toBe('peer_not_found')
        ->and($rig->wg->linkOrFail('wg0')->name)->toBe('wg0')
        ->and($rig->wg->peerOrFail('wg0', KeyManager::pubkeyToSafe($peer->public_key))->public_key)->toBe($peer->public_key)
        ->and($rig->wg->peerConfigOrFail('wg0', $peer->public_key))->toBe($peer->client_config);
});

it('takes a malformed link name or public key in a change for a mistake, not for something that is not there', function (Closure $change) {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $calls = count($rig->shell->calls);

    // Before the host is asked anything
    expect(fn () => $change($rig->wg, $peer->public_key))->toThrow(InvalidArgumentException::class)
        ->and(count($rig->shell->calls))->toBe($calls);
})->with([
    'a peer for a link no link can be' => [fn ($wg) => $wg->addPeer('no.such.link')],
    'a peer of such a link' => [fn ($wg, string $key) => $wg->removePeer('../etc', $key)],
    'removing a key that is none' => [fn ($wg) => $wg->removePeer('wg0', 'not-a-key')],
    'changing one' => [fn ($wg) => $wg->updatePeer('wg0', 'not-a-key', ['name' => 'x'])],
    'changing nothing of one' => [fn ($wg) => $wg->updatePeer('wg0', str_repeat('A', 20), [])],
    'new keys for one' => [fn ($wg) => $wg->rekeyPeer('wg0', str_repeat('A', 44))],
    'adopting a link no link can be' => [fn ($wg) => $wg->adoptLink('no.such.link')],
]);

it('fails instead of taking a link whose interface cannot be read for one that is not there', function (string $os) {
    $rig = new Rig($os);
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    $conf = $rig->host->conf('wg0');

    // It runs, but `wg show … dump` fails: this was read as "no such link" (a 404)
    $rig->shell->on('sudo -n :helper dump :iface', fn () => throw new CommandFailed('Unable to access interface: Operation not permitted'));
    expect(fn () => $rig->wg->getLink('wg0'))->toThrow(CommandFailedException::class, 'Operation not permitted')
        ->and(fn () => $rig->wg->getPeer('wg0', $peer->public_key))->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->linkOrFail('wg0'))->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->updatePeer('wg0', $peer->public_key, ['name' => 'x']))->toThrow(SystemException::class)
        ->and(fn () => $rig->wg->repairLink('wg0'))->toThrow(SystemException::class)
        ->and($rig->host->conf('wg0'))->toBe($conf);

    // And one that answers nothing at all is no link without a key either
    $rig->shell->on('sudo -n :helper dump :iface', fn () => '');
    expect(fn () => $rig->wg->getLink('wg0'))->toThrow(SystemException::class, 'could not be read');
})->with('os');

it('shows a link that stopped while it was looked at as its config has it', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $peer = $rig->wg->addPeer('wg0');
    // Listed as running, gone when its interface is read
    $rig->shell->on('sudo -n :helper dump :iface', function () use ($rig) {
        unset($rig->host->interfaces['wg0']);

        throw new CommandFailed('Unable to access interface: No such device');
    });

    $link = $rig->wg->getLink('wg0');

    expect($link->up)->toBeFalse()
        ->and($link->peers[0]->public_key)->toBe($peer->public_key);
});

it('says whether a link is the app\'s to change', function () {
    $rig = new Rig('linux');
    $rig->wg->createLink('wg0', '10.0.0.1/24', 51820);
    $rig->wg->createLink('wg1', '10.1.0.1/24', 51821, up: false);
    $rig->host->confs['office'] = handWrittenConf();
    $rig->host->addUnmanagedInterface('wg9');

    expect(array_map(fn (string $name) => $rig->wg->getLink($name)->toArray()['managed'], ['wg0', 'wg1', 'office', 'wg9']))->toBe([true, true, false, false]);

    // Also while it runs
    $rig->shell->run('sudo -n :helper up :name', ['name' => 'office']);
    expect($rig->wg->getLink('office'))->up->toBeTrue()->managed->toBeFalse();
});
