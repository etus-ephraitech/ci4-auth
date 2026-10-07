<?php

declare(strict_types=1);

namespace Ephraitech\Auth\Exceptions;

/**
 * Correct credentials, but the account is suspended, pending or inactive.
 * Only thrown AFTER the password is verified, so it never helps an
 * attacker learn anything about accounts they can't already access.
 */
final class AccountNotActiveException extends AuthException
{
    private const MESSAGES = [
        'suspended' => 'This account has been suspended.',
        'pending'   => 'This account is pending activation.',
        'inactive'  => 'This account is inactive.',
    ];

    public function __construct(
        private readonly string $status,
        private readonly ?string $reason = null,
    ) {
        parent::__construct(self::MESSAGES[$status] ?? 'This account cannot sign in.');
    }

    public function getStatus(): string
    {
        return $this->status;
    }

    /**
     * The admin-entered status_reason, if any.
     */
    public function getReason(): ?string
    {
        return $this->reason;
    }
}
