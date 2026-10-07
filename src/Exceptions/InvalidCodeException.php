<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * The code is wrong, expired, used up, or doesn't exist. Deliberately one
 * generic message for every case, so it reveals nothing about accounts.
 */
final class InvalidCodeException extends AuthException
{
    public function __construct(string $message = 'The code is invalid or has expired. Please request a new one.')
    {
        parent::__construct($message);
    }
}
