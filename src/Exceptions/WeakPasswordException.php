<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Thrown when a password fails the configured policy. Carries every
 * failed rule so forms can show all problems at once.
 */
final class WeakPasswordException extends AuthException
{
    /**
     * @param list<string> $errors
     */
    public function __construct(private readonly array $errors)
    {
        parent::__construct($errors[0] ?? 'The password does not meet the requirements.');
    }

    /**
     * @return list<string>
     */
    public function getErrors(): array
    {
        return $this->errors;
    }
}
