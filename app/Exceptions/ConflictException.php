<?php

namespace App\Exceptions;

use RuntimeException;

/**
 * The request clashes with existing state (rendered as 409).
 */
class ConflictException extends RuntimeException {}
