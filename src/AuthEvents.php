<?php

declare(strict_types=1);

namespace Ephraitech\Auth;

/**
 * Event names triggered through CodeIgniter\Events\Events.
 *
 *     Events::on(AuthEvents::REGISTERED, static function (User $user): void {
 *         // send welcome email / verification code
 *     });
 *
 * Events are triggered only after the related database work has committed.
 */
final class AuthEvents
{
    /** Payload: Ephraitech\Auth\Entities\User $user */
    public const REGISTERED = 'ephraitech.auth.registered';

    /** Payload: User $user, string $guard ('session'|'token') */
    public const LOGIN = 'ephraitech.auth.login';

    /** Payload: string|null $identifierType, string $identifier, string $reason */
    public const LOGIN_FAILED = 'ephraitech.auth.login_failed';

    /** Payload: string|null $identifierType, string $identifier, string $ipAddress */
    public const LOCKED_OUT = 'ephraitech.auth.locked_out';

    /** Payload: User $user, string $guard */
    public const LOGOUT = 'ephraitech.auth.logout';

    /** Payload: User $user */
    public const PASSWORD_CHANGED = 'ephraitech.auth.password_changed';

    /** Payload: int $userId, int $tokenId, string $type ('session'|'api_key') */
    public const TOKEN_ISSUED = 'ephraitech.auth.token_issued';

    /** Payload: int $userId, list<int> $tokenIds */
    public const TOKENS_REVOKED = 'ephraitech.auth.tokens_revoked';
}
