<?php

namespace App\Exceptions;

/**
 * The installed root helper is missing or isn't the one this app ships (e.g. the app was updated
 * but the helper wasn't reinstalled). Rendered as 500 with the fix in the message.
 */
class HelperException extends SystemException {}
