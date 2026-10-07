<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Too many failed attempts for this identifier from this IP address.
 */
final class LockedOutException extends AuthException
{
    public function __construct(private readonly int $retryAfter)
    {
        $minutes = max(1, (int) ceil($retryAfter / 60));

        parent::__construct(
            'Too many failed login attempts. Please try again in '
                . $minutes . ' minute' . ($minutes === 1 ? '' : 's') . '.'
        );
    }

    /**
     * Seconds until another attempt is allowed (for a Retry-After header).
     */
    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
