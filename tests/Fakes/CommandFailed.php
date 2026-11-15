<?php

namespace Tests\Fakes;

use App\Exceptions\CommandFailedException;

/**
 * A simulated non-zero exit status: the same type the real Shell throws.
 */
class CommandFailed extends CommandFailedException {}
