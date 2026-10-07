<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

use RuntimeException;

/**
 * Base exception for Ephraitech Auth. Host apps can catch this single type
 * to handle every package failure.
 */
class AuthException extends RuntimeException {}
