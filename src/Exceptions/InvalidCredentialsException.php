<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Credentials did not match. The default message is deliberately generic:
 * it never reveals whether the identifier exists or which part was wrong.
 */
final class InvalidCredentialsException extends AuthException
{
    public function __construct(string $message = 'The credentials provided are incorrect.')
    {
        parent::__construct($message);
    }
}
