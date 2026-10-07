<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

use Ephraitech\Auth\Config\Auth;

/**
 * Thrown when an email, username or phone fails normalization or validation.
 * Messages are safe to show to end users on registration/profile forms.
 * Never surface them on login forms (use a generic "invalid credentials").
 */
final class InvalidIdentifierException extends AuthException
{
    private const LABELS = [
        Auth::IDENTIFIER_EMAIL    => 'email address',
        Auth::IDENTIFIER_USERNAME => 'username',
        Auth::IDENTIFIER_PHONE    => 'phone number',
    ];

    private string $identifierType;

    public function __construct(string $message, string $identifierType = '')
    {
        parent::__construct($message);

        $this->identifierType = $identifierType;
    }

    public static function unsupportedType(string $type): self
    {
        return new self("Unsupported identifier type '{$type}'.", $type);
    }

    public static function notEnabled(string $type): self
    {
        return new self('Signing in with a ' . self::label($type) . ' is not enabled.', $type);
    }

    public static function empty(string $type): self
    {
        return new self('Please provide a ' . self::label($type) . '.', $type);
    }

    public static function invalid(string $type, string $reason): self
    {
        return new self('The ' . self::label($type) . ' ' . $reason . '.', $type);
    }

    public static function reserved(string $type): self
    {
        return new self('This ' . self::label($type) . ' is reserved and cannot be used.', $type);
    }

    public static function undetectable(): self
    {
        return new self('Could not determine the type of login identifier provided.');
    }

    public function getIdentifierType(): string
    {
        return $this->identifierType;
    }

    public static function label(string $type): string
    {
        return self::LABELS[$type] ?? $type;
    }
}
