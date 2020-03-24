<?php

namespace App\WireGuard;

use \Exception as BaseException;

class Exception extends BaseException
{
    public function __construct(string $message = "", int $code = 0, Throwable $previous = NULL)
    {
        parent::__construct($message, $code, $previous);
    }
}
