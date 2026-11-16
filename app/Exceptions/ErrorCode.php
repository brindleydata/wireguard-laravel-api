<?php

namespace App\Exceptions;

use Illuminate\Validation\ValidationException;
use InvalidArgumentException;
use Symfony\Component\HttpKernel\Exception\HttpExceptionInterface;
use Throwable;

/**
 * What went wrong, for a client that has to tell errors apart: the `code` next to `error` in
 * every error response (and in a command's `--json` failure). Messages are for people and may be
 * reworded; these are not.
 */
final class ErrorCode
{
    /** 404: no link of that name (no config, and no interface running under it). */
    public const LINK_NOT_FOUND = 'link_not_found';

    /** 404: the link is there, the peer is not. */
    public const PEER_NOT_FOUND = 'peer_not_found';

    /** 404: no such route (the framework's own). */
    public const ROUTE_NOT_FOUND = 'route_not_found';

    /** 405: the route doesn't take that method. */
    public const METHOD_NOT_ALLOWED = 'method_not_allowed';

    /** 409: the link's config has what the app doesn't write, so it isn't changed (see adopt). */
    public const UNMANAGED_CONFIG = 'unmanaged_config';

    /** 409: a WireGuard interface that runs without a config here: shown, never changed. */
    public const UNMANAGED_INTERFACE = 'unmanaged_interface';

    /** 409: adopt asked for a link the app manages already. */
    public const ALREADY_MANAGED = 'already_managed';

    /** 409: adopt asked for a config with something that can't be carried over. */
    public const NOT_ADOPTABLE = 'not_adoptable';

    /** 409: the request clashes with what is there (a port, a subnet, a name, a route, a policy). */
    public const CONFLICT = 'conflict';

    /** 422: a value, a field or a name the request can't have. */
    public const INVALID_INPUT = 'invalid_input';

    /** 403: no API key, or a wrong one. */
    public const UNAUTHORIZED = 'unauthorized';

    /** 429: too many requests (with a wrong API key). */
    public const RATE_LIMITED = 'rate_limited';

    /** 500: the host failed to do what was asked, or couldn't be asked. */
    public const SYSTEM_ERROR = 'system_error';

    /** Any other refusal of the framework's (4xx). */
    public const REQUEST_REFUSED = 'request_refused';

    public static function of(Throwable $e): string
    {
        return match (true) {
            $e instanceof NotFoundException, $e instanceof ConflictException => $e->errorCode,
            $e instanceof InvalidArgumentException, $e instanceof ValidationException => self::INVALID_INPUT,
            $e instanceof HttpExceptionInterface => self::ofStatus($e->getStatusCode()),
            default => self::SYSTEM_ERROR,
        };
    }

    /** For what the framework refuses itself, which only has a status. */
    public static function ofStatus(int $status): string
    {
        return match (true) {
            $status === 401, $status === 403 => self::UNAUTHORIZED,
            $status === 404 => self::ROUTE_NOT_FOUND,
            $status === 405 => self::METHOD_NOT_ALLOWED,
            $status === 400, $status === 422 => self::INVALID_INPUT,
            $status === 429 => self::RATE_LIMITED,
            $status >= 500 => self::SYSTEM_ERROR,
            default => self::REQUEST_REFUSED,
        };
    }
}
