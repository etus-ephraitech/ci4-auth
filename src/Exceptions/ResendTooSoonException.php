<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * A code was requested again before $otpResendInterval elapsed.
 */
final class ResendTooSoonException extends AuthException
{
    public function __construct(private readonly int $retryAfter)
    {
        parent::__construct(
            'Please wait ' . $retryAfter . ' second' . ($retryAfter === 1 ? '' : 's')
                . ' before requesting another code.'
        );
    }

    public function getRetryAfter(): int
    {
        return $this->retryAfter;
    }
}
