<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * The request clashes with existing state (rendered as 409). `errorCode` is `conflict` unless
 * the clash is one a client acts on by itself: a config the app doesn't manage, an interface
 * something else started, an adoption that isn't needed or isn't possible.
 */
class ConflictException extends RuntimeException
{
    public function __construct(string $message = '', public readonly string $errorCode = ErrorCode::CONFLICT)
    {
        parent::__construct($message);
    }
}
