<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * The host failed to do what was asked: a system command, file or lock problem (rendered as 500
 * with its message, so API clients can see e.g. a missing sudoers rule).
 */
class SystemException extends RuntimeException {}
