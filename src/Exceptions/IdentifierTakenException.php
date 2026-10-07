<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Thrown when an identifier is already registered to another account.
 */
final class IdentifierTakenException extends AuthException
{
    private string $identifierType;

    public function __construct(string $message, string $identifierType)
    {
        parent::__construct($message);

        $this->identifierType = $identifierType;
    }

    public static function forType(string $type): self
    {
        return new self(
            'This ' . InvalidIdentifierException::label($type) . ' is already in use.',
            $type
        );
    }

    public function getIdentifierType(): string
    {
        return $this->identifierType;
    }
}
