<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Correct credentials, but the identifier used must be verified first.
 * Carries the user ID so the host can offer "resend verification".
 */
final class IdentifierNotVerifiedException extends AuthException
{
    public function __construct(
        private readonly string $identifierType,
        private readonly int $userId,
    ) {
        parent::__construct(
            'Please verify your ' . InvalidIdentifierException::label($identifierType) . ' before signing in.'
        );
    }

    public function getIdentifierType(): string
    {
        return $this->identifierType;
    }

    public function getUserId(): int
    {
        return $this->userId;
    }
}
