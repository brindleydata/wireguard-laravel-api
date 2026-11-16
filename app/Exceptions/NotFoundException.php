<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * A link or a peer that isn't there (rendered as 404). `errorCode` says which: nothing else that
 * answers 404 has these codes.
 */
class NotFoundException extends RuntimeException
{
    public function __construct(string $message = '', public readonly string $errorCode = ErrorCode::LINK_NOT_FOUND)
    {
        parent::__construct($message);
    }

    public static function link(string $name): self
    {
        return new self("Link does not exist: {$name}", ErrorCode::LINK_NOT_FOUND);
    }

    public static function peer(string $pubkey): self
    {
        return new self("Peer not found: {$pubkey}", ErrorCode::PEER_NOT_FOUND);
    }
}
